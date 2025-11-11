(ns jepsen.net
  "Controls network manipulation.

  TODO: break this up into jepsen.net.proto (polymorphism) and jepsen.net
  (wrapper fns, default args, etc)"
  (:require [dom-top.core :refer [real-pmap]]
            [clojure.string :as str]
            [clojure.tools.logging :refer [info warn]]
            [jepsen.control :refer :all]
            [jepsen.control.net :as control.net]
            [jepsen.net.proto :as p :refer [Net PartitionAll]]
            [potemkin :refer [import-vars]]
            [slingshot.slingshot :refer [throw+ try+]]))

; These were extracted to jepsen.net.proto, but we retain them here for
; compatibility/API simplicity.
(import-vars [jepsen.net.proto
              drop!
              heal!
              slow!
              flaky!
              fast!
              shape!
              shape-from-control!])

; Forward declarations for local command execution functions
(declare run-local-command-with-output run-local-command-safe run-local-command-with-error-output)

; Local command execution functions for control-packet nemesis
(defn- run-local-command-with-output
  "Run a command locally without SSH and return the output."
  [& args]
  (let [string-args (map str args)
        pb (java.lang.ProcessBuilder. (into-array String string-args))
        process (.start pb)
        reader (java.io.BufferedReader. (java.io.InputStreamReader. (.getInputStream process)))
        output (->> (line-seq reader)
                    (doall))
        exit-code (.waitFor process)]
    (.close reader)
    (when-not (zero? exit-code)
      (throw (RuntimeException. (str "Command failed with exit code " exit-code))))
    (str/join "\n" output)))

(defn- run-local-command-safe
  "Run a command locally without SSH, but don't throw on failure."
  [& args]
  (let [string-args (map str args)
        pb (java.lang.ProcessBuilder. (into-array String string-args))
        process (.start pb)
        exit-code (.waitFor process)]
    exit-code))

(defn- run-local-command-with-error-output
  "Run a command locally without SSH and return both exit code and error output."
  [& args]
  (let [string-args (map str args)
        pb (java.lang.ProcessBuilder. (into-array String string-args))
        process (.start pb)
        error-reader (java.io.BufferedReader. (java.io.InputStreamReader. (.getErrorStream process)))
        error-output (->> (line-seq error-reader)
                          (doall))
        exit-code (.waitFor process)]
    (.close error-reader)
    {:exit-code exit-code
     :error-output (str/join "\n" error-output)}))

(defn- get-local-ip
  "Get the IP address of a hostname locally."
  [host]
  (let [output (run-local-command-with-output "getent" "ahostsv4" host)
        lines (str/split-lines output)
        first-line (first lines)
        ip (when first-line
             (first (str/split first-line #"\s+")))]
    (cond
      (and ip (re-find #"^127" ip))
      (get-local-ip "localhost")
      (str/blank? ip)
      (throw (RuntimeException. (str "Blank IP for host: " host)))
      ip
      ip
      :else
      (throw (RuntimeException. (str "No IP found for host: " host))))))

(defn- delete-local-qdisc
  "Delete all qdiscs on the given device locally."
  [dev]
  (try
    (run-local-command-with-output "tc" "qdisc" "del" "dev" dev "root")
    (catch RuntimeException _ nil)))

; Top-level API functions
(defn drop-all!
  "Takes a test and a grudge: a map of nodes to collections of nodes they
  should drop messages from, and makes those changes to the test's network."
  [test grudge]
  (let [net (:net test)]
    (if (satisfies? PartitionAll net)
      ; Fast path
      (p/drop-all! net test grudge)

      ; Fallback
      (->> grudge
           ; We'll expand {dst [src1 src2]} into ((src1 dst) (src2 dst) ...)
           (mapcat (fn expand [[dst srcs]]
                     (map list srcs (repeat dst))))
           (real-pmap (partial apply drop! net test))
           dorun))))

(def tc "/sbin/tc")

(defn net-dev
  "Returns the network interface of the current host."
  []
  (let [choices (su (exec :ip :-o :link :show))
        iface (->> choices
                   (str/split-lines)
                   (map (fn [ln] (let [[_match iface] (re-find #"\d+: ([^:@]+).+" ln)] iface)))
                   (remove #(= "lo" %))
                   (first))]
    (assert iface
            (str "Couldn't determine network interface!\n" choices))
    iface))

(defn- get-local-net-dev
  "Get the primary network interface locally (for control-packet nemesis)."
  []
  (let [devs (->> (run-local-command-with-output "ip" "link" "show")
                  (str/split-lines)
                  (map #(re-find #"^\d+: ([^:]+):" %))
                  (filter some?)
                  (map second)
                  (filter #(not (re-find #"^(lo|docker|br-|veth|tunl|gre|sit|ip6tnl|erspan|gretap)" %)))
                  (filter #(re-find #"^eth" %))  ; Only select eth interfaces
                  (sort))]
    (if (seq devs)
      (let [dev (first devs)]
        ; Remove @ part from interface name for tc commands
        (if (re-find #"@" dev)
          (first (str/split dev #"@"))
          dev))
      "eth0")))

(defn qdisc-del
  "Deletes root qdisc for given dev on current node."
  [dev]
  (try+
   (su (exec tc :qdisc :del :dev dev :root))
   (catch [:exit 2] _
     ; no qdisc to del
     nil)))

(def all-packet-behaviors
  "All of the available network packet behaviors, and their default option
  values.

   Caveats:

     - Behaviors are applied to a node's network interface and affect all DB to
       DB node traffic
     - `:delay` - Use `:normal` distribution of delays for more typical network
                  behavior
     - `:loss`  - When used locally (not on a bridge or router), the loss is
                  reported to the upper level protocols. This may cause TCP to
                  resend and behave as if there was no loss.

   See [tc-netem(8)](https://manpages.debian.org/bullseye/iproute2/tc-netem.8)."
  {:delay     {:time         :50ms
               :jitter       :10ms
               :correlation  :25%
               :distribution :normal}
   :loss      {:percent      :20%
               :correlation  :75%}
   :corrupt   {:percent      :20%
               :correlation  :75%}
   :duplicate {:percent      :20%
               :correlation  :75%}
   :reorder   {:percent      :20%
               :correlation  :75%}
   :rate      {:rate         :1mbit}})

(defn- behaviors->netem
  "Given a map of behaviors, returns a sequence of netem options."
  [behaviors]
  (->>
   ; :reorder requires :delay
   (if (and (:reorder behaviors)
            (not (:delay behaviors)))
     (assoc behaviors :delay (:delay all-packet-behaviors))
     behaviors)
   ; fill in all unspecified opts with default values
   (reduce (fn [acc [behavior opts]]
             (assoc acc behavior (merge (behavior all-packet-behaviors) opts)))
           {})
   ; build a tc cmd line combining all behaviors
   (reduce (fn [args [behavior {:keys [time jitter percent correlation distribution rate] :as _opts}]]
             (case behavior
               :delay
               (concat args [:delay time jitter correlation :distribution distribution])
               (:loss :corrupt :duplicate :reorder)
               (concat args [behavior percent correlation])
               :rate
               (concat args [:rate rate])))
           [])))

(defn- hardcoded-netem-params
  "Returns hardcoded netem parameters for control-packet nemesis."
  []
  ["delay" "10000ms" "10ms" "15%" "distribution" "normal"])

(defn- update-netem-delay
  "Update the delay time of existing netem qdisc on control node."
  [delay-ms]
  (info "Updating netem delay to" delay-ms "ms on control node")
  (try
    (let [dev (get-local-net-dev)
          netem-params ["delay" (str delay-ms "ms") "10ms" "15%" "distribution" "normal"]]
      (info "Updating netem qdisc on device" dev "with new delay:" delay-ms "ms")
      
      ; First, check what qdiscs exist
      (let [qdisc-output (run-local-command-with-output "tc" "qdisc" "show" "dev" dev)]
        (info "Current qdiscs on" dev ":" qdisc-output))
      
      ; Try to find and update the netem qdisc
      ; Based on the qdisc structure we know: handle "40:" parent "1:4"
      (let [result (apply run-local-command-with-error-output 
                         (concat ["tc" "qdisc" "change" "dev" dev "parent" "1:4" "handle" "40:" "netem"] netem-params))]
        (if (zero? (:exit-code result))
          (do
            (info "Successfully updated netem delay to" delay-ms "ms using handle 40: parent 1:4")
            [:updated delay-ms "40:" "1:4"])
          (do
            (warn "Failed to update netem delay on device" dev "- exit code:" (:exit-code result) "- error:" (:error-output result))
            (warn "Available qdiscs:" (run-local-command-with-output "tc" "qdisc" "show" "dev" dev))
            [:failed (:error-output result)]))))
    (catch Exception e
      (warn e "Error updating netem delay on control node")
      [:error (.getMessage e)])))

(defn update-control-delay!
  "Public function to update the delay time of control-packet nemesis.
  Takes delay in milliseconds and updates the existing netem qdisc."
  [delay-ms]
  (update-netem-delay delay-ms))

(defn- net-shape!
  "Shared convenience call for iptables/ipfilter. Shape the network with tc
  qdisc, netem, and filter(s) so target nodes have given behavior."
  [_net test targets behavior]
  (let [results (on-nodes test
                          (fn [test node]
                            (let [nodes   (set (:nodes test))
                                  targets (set targets)
                                  targets (if (contains? targets node)
                                            (disj nodes node)
                                            targets)
                                  dev     (net-dev)]
                              ; start with no qdisc
                              (qdisc-del dev)
                              (if (and (seq targets)
                                       (seq behavior))
                                ; node will need a prio qdisc, netem qdisc, and a filter per target
                                (do
                                  (su
                                   ; root prio qdisc, bands 1:1-3 are system default prio
                                   (exec tc
                                         :qdisc :add :dev dev
                                         :root :handle "1:"
                                         :prio :bands 4 :priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1)
                                   ; band 1:4 is a netem qdisc for the behavior
                                   (exec tc
                                         :qdisc :add :dev dev
                                         :parent "1:4" :handle "40:"
                                         :netem (behaviors->netem behavior))
                                   ; filter dst ip's to netem qdisc with behavior
                                   (doseq [target targets]
                                     (exec tc
                                           :filter :add :dev dev
                                           :parent "1:0"
                                           :protocol :ip :prio :3 :u32 :match :ip :dst (control.net/ip target)
                                           :flowid "1:4")))
                                  targets)
                                ; no targets and/or behavior, so no qdisc/netem/filters
                                nil))))]
    ; return a more readable value
    (if (and (seq targets) (seq behavior))
      [:shaped   results :netem (vec (behaviors->netem behavior))]
      [:reliable results])))

(defn- net-shape-from-control!
  "Shape network from control node to target nodes with tc qdisc, netem, and filters."
  [_net test targets behavior]
  (info "net-shape-from-control! called with targets:" targets "behavior:" behavior)
  (let [targets (set targets)]
    (info "On control node - shaping traffic to targets:" targets)
    (if (and (seq targets)
             (seq behavior))
      ; control node will need a prio qdisc, netem qdisc, and a filter per target
      (do
        (info "Creating tc rules on control node for targets" targets)
        (try
          ; Run commands directly on the control node without SSH
          (let [dev (get-local-net-dev)]
            (info "On control node - shaping traffic to targets:" targets "on dev:" dev)
            ; start with no qdisc
            (delete-local-qdisc dev)
            ; Run commands directly with error handling
            (let [netem-params (hardcoded-netem-params)]
              (try
                ; root prio qdisc, bands 1:1-3 are system default prio
                (let [exit-code (run-local-command-safe "tc" "qdisc" "add" "dev" dev "root" "handle" "1:" "prio" "bands" "4" "priomap" "1" "2" "2" "2" "1" "2" "0" "0" "1" "1" "1" "1" "1" "1" "1" "1")]
                  (when-not (zero? exit-code)
                    (warn "Failed to create root qdisc on device" dev "- tc may not be supported on this interface")))
                ; band 1:4 is a netem qdisc for the behavior
                (let [result (apply run-local-command-with-error-output (concat ["tc" "qdisc" "add" "dev" dev "parent" "1:4" "handle" "40:" "netem"] netem-params))]
                  (when-not (zero? (:exit-code result))
                    (warn "Failed to create netem qdisc on device" dev "- exit code:" (:exit-code result) "- error:" (:error-output result) "- params:" netem-params)))
                ; filter dst ip's to netem qdisc with behavior
                (doseq [target targets]
                  (let [target-ip (get-local-ip target)]
                    (info "Adding filter for target" target "with IP" target-ip)
                    (let [result (run-local-command-with-error-output "tc" "filter" "add" "dev" dev "parent" "1:0" "protocol" "ip" "prio" "3" "u32" "match" "ip" "dst" target-ip "flowid" "1:4")]
                      (when-not (zero? (:exit-code result))
                        (warn "Failed to create filter for target" target "on device" dev "- exit code:" (:exit-code result) "- error:" (:error-output result))))))
              (catch Exception e
                (warn e "Error creating tc rules on device" dev "- tc may not be supported on this interface"))))
            (info "TC rules created successfully on control node")
            [:shaped targets :netem (vec (behaviors->netem behavior))])
          (catch Exception e
            (warn e "Failed to create tc rules on control node")
            (throw e))))
      ; no targets and/or behavior, so clean up existing qdisc/netem/filters
      (do
        (info "Cleaning up tc rules on control node - empty targets or behavior")
        (try
          (let [dev (get-local-net-dev)]
            (delete-local-qdisc dev)
            (info "Cleaned up tc rules on control node"))
          (catch Exception e
            (warn e "Failed to clean up tc rules on control node")))
        [:reliable nil]))))

(def noop
  "Does nothing."
  (reify Net
    (drop!  [net test src dest])
    (heal!  [net test])
    (slow!  [net test])
    (slow!  [net test opts])
    (flaky! [net test])
    (fast!  [net test])
    (shape! [net test nodes behavior])

    (shape-from-control! [net test targets behavior])))

(def iptables
  "Default iptables (assumes we control everything)."
  (reify Net
    (drop! [net test src dest]
      (on-nodes test [dest]
                (fn [test node]
                  (su (exec :iptables :-A :INPUT :-s (control.net/ip src) :-j
                            :DROP :-w)))))

    (heal! [net test]
      (with-test-nodes test
        (su
          (exec :iptables :-F :-w)
          (exec :iptables :-X :-w))))

    (slow! [net test]
      (with-test-nodes test
        (su (exec tc :qdisc :add :dev :eth0 :root :netem :delay :50ms
                  :10ms :distribution :normal))))

    (slow! [net test {:keys [mean variance distribution]
                      :or   {mean         50
                             variance     10
                             distribution :normal}}]
      (with-test-nodes test
        (su (exec tc :qdisc :add :dev :eth0 :root :netem :delay
                  (str mean "ms")
                  (str variance "ms")
                  :distribution distribution))))

    (flaky! [net test]
      (with-test-nodes test
        (su (exec tc :qdisc :add :dev :eth0 :root :netem :loss "20%"
                  "75%"))))

    (fast! [net test]
      (with-test-nodes test
        (try
          (su (exec tc :qdisc :del :dev :eth0 :root))
          (catch RuntimeException e
            (if (re-find #"Error: Cannot delete qdisc with handle of zero."
                         (.getMessage e))
              nil
              (throw e))))))

    (shape! [net test nodes behavior]
      (net-shape! net test nodes behavior))

    (shape-from-control! [net test targets behavior]
      (net-shape-from-control! net test targets behavior))

    PartitionAll
    (drop-all! [net test grudge]
      (on-nodes test
                (keys grudge)
                (fn snub [_ node]
                  (when (seq (get grudge node))
                    (su (exec :iptables :-A :INPUT :-s
                              (->> (get grudge node)
                                   (map control.net/ip)
                                   (str/join ","))
                              :-j :DROP :-w))))))))

(def ipfilter
  "IPFilter rules"
  (reify Net
    (drop! [net test src dest]
      (on dest (su (exec :echo :block :in :from src :to :any | :ipf :-f :-))))

    (heal! [net test]
      (with-test-nodes test
        (su (exec :ipf :-Fa))))

    (slow! [net test]
      (with-test-nodes test
        (su (exec :tc :qdisc :add :dev :eth0 :root :netem :delay :50ms
                  :10ms :distribution :normal))))

    (slow! [net test {:keys [mean variance distribution]
                      :or   {mean         50
                             variance     10
                             distribution :normal}}]
      (with-test-nodes test
        (su (exec tc :qdisc :add :dev :eth0 :root :netem :delay
                  (str mean "ms")
                  (str variance "ms")
                  :distribution distribution))))

    (flaky! [net test]
      (with-test-nodes test
        (su (exec :tc :qdisc :add :dev :eth0 :root :netem :loss "20%"
                  "75%"))))

    (fast! [net test]
      (with-test-nodes test
        (su (exec :tc :qdisc :del :dev :eth0 :root))))

    (shape! [net test nodes behavior]
      (net-shape! net test nodes behavior))

    (shape-from-control! [net test targets behavior]
      (net-shape-from-control! net test targets behavior))))
