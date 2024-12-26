
/**
 * @file ddosDetector.h
 * @brief This file contains the declaration of the ddosDetector class which implements detection of DDoS attacks using CUSUMs.
 * @author Mikuláš Brázda
 * @date 15.05.2024
 */

#pragma once

#include "adaptiveCusum.h"
#include "CountMinSketch.h"
#include <atomic>
#include <mutex>
#include <thread>
#include "ddosDetectorValue.h"
#include <condition_variable>
#include <bitset>
#include "threadSafeQueue.h"
#include <unordered_map>
#include <optional>
#include "common.h"
#include "threadSafePipe.h"
#include "trie.h"
#include <map>

/**
 * @brief Enumeration for the types of alerts.
 */
typedef enum {
    DOS,    /**< Denial of Service */
    DDOS    /**< Distributed Denial of Service */
} alertType_t;

/**
 * @brief Structure representing a DOS alert.
 */
typedef struct dos_alert {
    double thresholdBytes;                  /**< Threshold for bytes */
    double thresholdPackets;                /**< Threshold for packets */
    double thresholdBytesReceivedToSent;    /**< Threshold for bytes received to sent ratio */
    double thresholdFlowsReceivedToSent;    /**< Threshold for flows received to sent ratio */
    double thresholdEntropy;                /**< Threshold for entropy */
    double measuredBytes;                   /**< Measured bytes */
    double measuredPackets;                 /**< Measured packets */
    double measuredBytesReceivedToSent;     /**< Measured bytes received to sent ratio */
    double measuredFlowsReceivedToSent;     /**< Measured flows received to sent ratio */
    double measuredEntropy;                 /**< Measured entropy */
    uint32_t dstIP;                         /**< Destination IP */
    uint32_t cusumID;                       /**< CUSUM ID */
    std::set<uint32_t> srcIPs;              /**< Set of source IPs */
} dos_alert_t;

/**
 * @brief Alias for CountMinSketch with destination IPs.
 */
using BCSketchTypeDstIPs = CountMinSketch<std::bitset<32>, ddosDetectorValue>;

/**
 * @brief Alias for CountMinSketch with source IPs.
 */
using BCSketchTypeSrcIPs = CountMinSketch<std::bitset<32>, binCountSketchValue<32>>;

/**
 * @brief Alias for time point.
 */
using timePoint = std::chrono::time_point<std::chrono::system_clock>;

/**
 * @brief Structure representing the values in the pipe.
 */
struct PipeValue {
    BCSketchTypeDstIPs dstIPs;  /**< CountMinSketch with destination IPs */
    BCSketchTypeSrcIPs srcIPs;  /**< CountMinSketch with source IPs */

    /**
     * @brief Constructor for PipeValue.
     * @param dstIPs CountMinSketch with destination IPs
     * @param srcIPs CountMinSketch with source IPs
     */
    PipeValue(BCSketchTypeDstIPs dstIPs, BCSketchTypeSrcIPs srcIPs) : dstIPs(dstIPs), srcIPs(srcIPs) {}
};

/**
 * @brief Class representing the DDoS detector.
 */
class ddosDetector {

public:
    /**
     * @brief Constructor for ddosDetector.
     * @param protectedPrefixes Trie containing protected prefixes
     * @param whitelistedPrefixes Optional Trie containing whitelisted prefixes
     * @param learningSecs Learning period in seconds
     * @param quantile Quantile value for threshold calculation
     * @param alpha Alpha value for CUSUM algorithm
     * @param span Span value for CUSUM algorithm
     * @param c C value for CUSUM algorithm
     * @param outerSizeDstIPs Outer size for CountMinSketch with destination IPs
     * @param innerSizeDstIPs Inner size for CountMinSketch with destination IPs
     * @param outerSizeSrcIPs Outer size for CountMinSketch with source IPs
     * @param innerSizeSrcIPs Inner size for CountMinSketch with source IPs
     * @param n Number of CUSUMs
     * @param timeBetweenAlertsSecs Time between consecutive alerts in seconds
     */
    ddosDetector(Trie<float>& protectedPrefixes, 
                    std::optional<Trie<>>& whitelistedPrefixes, 
                    size_t learningSecs,
                    float quantile,
                    float alpha,
                    uint32_t span,
                    float c,
                    size_t outerSizeDstIPs,
                    size_t innerSizeDstIPs,
                    size_t outerSizeSrcIPs,
                    size_t innerSizeSrcIPs,
                    int n,
                    int timeBetweenAlertsSecs);

    /**
     * @brief Process the current flow record.
     * @param record The netflow record to process
     */
    void processCurrentFlow(const netflowRecord_t& record);

    /**
     * @brief Run the detector thread.
     */
    void runDetectorThread();

    /**
     * @brief Check if the given IP is protected.
     * @param inputIP The IP to check
     * @return True if the IP is protected, false otherwise
     */
    bool isProtected(uint32_t inputIP) const;

    /**
     * @brief Check if the given IP is whitelisted.
     * @param inputIP The IP to check
     * @return True if the IP is whitelisted, false otherwise
     */
    bool isWhitelisted(uint32_t inputIP) const;

    /**
     * @brief Notify the worker thread.
     */
    void notifyWorker();

    /**
     * @brief Get the next alert from the queue.
     * @param alert The dos_alert_t structure to store the alert
     * @return True if an alert is available, false otherwise
     */
    bool getAlert(dos_alert_t& alert);

    /**
     * @brief Push a false positive alert to the queue.
     * @param alert The false positive alert to push
     */
    void pushFalsePositive(const dos_alert_t& alert);

    /**
     * @brief Destructor for ddosDetector.
     */
    ~ddosDetector();

private:
    /**
     * @brief The main detection process.
     */
    void detectionProcess();

    /**
     * @brief Calculate the normalized entropy.
     * @param counts Vector of counts
     * @return The normalized entropy value
     */
    float calculateNormalizedEntropy(std::vector<uint32_t> counts);

    /**
     * @brief Update the communicatedWith map.
     * @param srcIP Source IP
     * @param dstIP Destination IP
     * @param bytes Number of bytes
     * @param isDst Flag indicating if the IP is the destination IP
     */
    void updateCommunicatedWith(uint32_t srcIP, uint32_t dstIP, uint64_t bytes, bool isDst);

    /**
     * @brief Reverse the source IPs.
     * @param communicatedWith Map of communicated IPs
     * @param srcIPsCommWithDstVec Vector to store the reversed source IPs
     * @param rows Map of rows
     * @param srcIPsCopy Copy of the source IPs CountMinSketch
     */
    void reverseSrcIPs(const std::unordered_map<uint32_t, uint32_t>& communicatedWith, 
                                    std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDstVec, 
                                    const std::map<uint32_t, uint32_t>& rows, 
                                    BCSketchTypeSrcIPs& srcIPsCopy);

    /**
     * @brief Get the quantile threshold high value.
     * @tparam T Type of the CUSUMs
     * @param allCusums Vector of all CUSUMs
     * @return The quantile threshold high value
     */
    template<typename T>
    float getQuantileThresholdHigh(const T& allCusums);

    /**
     * @brief Get the quantile threshold low value.
     * @tparam T Type of the CUSUMs
     * @param allCusums Vector of all CUSUMs
     * @return The quantile threshold low value
     */
    template<typename T>
    float getQuantileThresholdLow(const T& allCusums);

    /**
     * @brief Get the multiplier for the given IP.
     * @param ip The IP to get the multiplier for
     * @return The multiplier value
     */
    float getMultiplier(uint32_t ip);

    /**
     * @brief Set the CUSUM threshold low value.
     * @param cusum The CUSUM to set the threshold for
     * @param quantileThreshold The quantile threshold value
     */
    void setCusumThresholdLow(AdaptiveCUSUM& cusum, float quantileThreshold);

    /**
     * @brief Set the CUSUM threshold high value.
     * @param cusum The CUSUM to set the threshold for
     * @param quantileThreshold The quantile threshold value
     */
    void setCusumThresholdHigh(AdaptiveCUSUM& cusum, float quantileThreshold);

    /**
     * @brief Get the top N source IPs.
     * @param srcIPsCommWithDst Vector of source IPs communicated with the destination IP
     * @param topNSrcIPs Set to store the top N source IPs
     */
    void getTopNSrcIPs(std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst, std::set<uint32_t>& topNSrcIPs);

    /**
     * @brief Set the CUSUM thresholds.
     */
    void setCusumTresholds();

    /**
     * @brief Initialize the log and stats files.
     */
    void initFiles();

    /**
     * @brief Close the log and stats files.
     */
    void closeFiles();

    /**
     * @brief Update the thresholds.
     */
    void updateThresholds();

    /**
     * @brief Check for false positives.
     */
    void checkFalsePositives(); 

    /**
     * @brief Reverse all keys.
     * @param maxIP Maximum IP value
     * @param resultCell Result cell
     * @param dstIPs CountMinSketch with destination IPs
     * @param srcIPs CountMinSketch with source IPs
     * @param column Column index
     * @param reversedSrcIPsCommWithDst Vector to store the reversed source IPs communicated with the destination IP
     * @param reversedPrefixes Set to store the reversed prefixes
     */
    void reverseAllKeys(uint32_t& maxIP, ddosDetectorValue& resultCell, BCSketchTypeDstIPs& dstIPs, 
                                BCSketchTypeSrcIPs& srcIPs, uint32_t column, 
                                std::vector<std::pair<uint32_t, uint32_t>>& reversedSrcIPsCommWithDst, 
                                std::set<uint32_t>& reversedPrefixes);

    /**
     * @brief Compute the metrics.
     * @param entropy Entropy value
     * @param receivedToSentBytes Received to sent bytes ratio
     * @param receivedToSentFlows Received to sent flows ratio
     * @param srcIPsCommWithDst Vector of source IPs communicated with the destination IP
     * @param resultCell Result cell
     */
    void computeMetrics(double& entropy,
                            double& receivedToSentBytes, double& receivedToSentFlows, 
                            std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst,
                            ddosDetectorValue& resultCell);

    /**
     * @brief Update the metrics.
     * @param srcIPsCommWithDst Vector of source IPs communicated with the destination IP
     * @param dstIpsReversed Set of reversed destination IPs
     * @param resultCell Result cell
     * @param learning Flag indicating if the detector is in learning mode
     * @param column Column index
     */
    void updateMetrics(std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst, std::set<uint32_t>& dstIpsReversed,
                                ddosDetectorValue& resultCell, bool learning, uint32_t column);

    /**
     * @brief Update the stats file.
     * @param dstIpsReversed Set of reversed destination IPs
     * @param j Index
     * @param resultCell Result cell
     * @param entropy Entropy value
     * @param sentReceivedBytesRatio Sent to received bytes ratio
     * @param sentReceivedFlowsRatio Sent to received flows ratio
     */
    void updateStatsFile(std::set<uint32_t>& dstIpsReversed, 
                                    uint32_t j, const ddosDetectorValue& resultCell, 
                                    float entropy, 
                                    float sentReceivedBytesRatio, 
                                    float sentReceivedFlowsRatio);

    /**
     * @brief Detect an anomaly.
     * @param maxIP Maximum IP value
     * @param column Column index
     * @param srcIPsCommWithDst Vector of source IPs communicated with the destination IP
     * @return True if an anomaly is detected, false otherwise
     */
    bool detectAnomaly(uint32_t maxIP, uint32_t column, std::vector<std::pair<uint32_t, uint32_t>>& srcIPsCommWithDst);

    const size_t innerSizeDstIPs;    /**< Inner size for CountMinSketch with destination IPs */
    const size_t innerSizeSrcIPs;    /**< Inner size for CountMinSketch with source IPs */
    const size_t outerSizeDstIPs;    /**< Outer size for CountMinSketch with destination IPs */
    const size_t outerSizeSrcIPs;    /**< Outer size for CountMinSketch with source IPs */
    BCSketchTypeDstIPs dstIPs;       /**< CountMinSketch with destination IPs */
    BCSketchTypeSrcIPs srcIPs;       /**< CountMinSketch with source IPs */
    std::vector<AdaptiveCUSUM> cusumBytes;               /**< Vector of CUSUMs for bytes */
    std::vector<AdaptiveCUSUM> cusumPackets;             /**< Vector of CUSUMs for packets */
    std::vector<AdaptiveCUSUM> cusumEntropy;             /**< Vector of CUSUMs for entropy */
    std::vector<AdaptiveCUSUM> cusumBytesReceivedToSent; /**< Vector of CUSUMs for bytes received to sent ratio */
    std::vector<AdaptiveCUSUM> cusumFlowsReceivedToSent; /**< Vector of CUSUMs for flows received to sent ratio */
    std::thread detectorThread;                          /**< Detector thread */
    bool stop;                                           /**< Flag indicating if the detector should stop */
    Trie<float>& protectedPrefixes;                      /**< Trie containing protected prefixes */
    Trie<> whitelistedPrefixes;                          /**< Trie containing whitelisted prefixes */
    ThreadSafeQueue<dos_alert_t> dosAlertsQueue;          /**< Queue for DOS alerts */
    ThreadSafeQueue<dos_alert_t> dosFalsePositivesQueue;  /**< Queue for false positive alerts */
    ThreadSafePipe<PipeValue> pipe;                       /**< Pipe for communication between threads */
    const size_t learningSecs_;                           /**< Learning period in seconds */
    const float quantile_;                                /**< Quantile value for threshold calculation */
    const int n_;                                         /**< Number of CUSUMs */
    int timeBetweenAlertsSecs_;                           /**< Time between consecutive alerts in seconds */
    std::ofstream logFile;                                /**< Log file */
    std::ofstream statsFile;                              /**< Stats file */
};
