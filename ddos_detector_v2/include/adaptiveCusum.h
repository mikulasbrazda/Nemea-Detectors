/**
 * @file adaptiveCusum.h
 * @brief Contains the declaration of the AdaptiveCUSUM class.
 * @author Mikuláš Brázda (xbrazd21@stud.fit.vutbr.cz)
 * @date 15.05.2024
 */
#pragma once 
#include <cstdint>
#include "timeManager.h"
/**
 * @class AdaptiveCUSUM
 * @brief Represents an adaptive CUSUM algorithm for anomaly detection.
 * 
 * The algorithm calculates the CUSUM statistics for detecting positive and negative anomalies
 * based on the current observation and previous observations.
 */
class AdaptiveCUSUM {
public:
    /**
     * @brief Constructs an AdaptiveCUSUM object with the specified parameters.
     * 
     * @param c The model parameter.
     * @param alpha The smoothing factor for the exponentially weighted moving average (EWMA) of the mean.
     * @param span The number of previous observations to consider for calculating the mean and variance.
     */
    AdaptiveCUSUM(double c, double alpha, uint32_t span);

    /**
     * @brief Processes the current observation and updates the CUSUM statistics.
     * 
     * @param currentValue The value of the current observation.
     * @param learning Indicates whether the algorithm is in the learning phase.
     */
    void process(double currentValue, bool learning);

    /**
     * @brief Gets the value of the positive anomaly CUSUM statistic (SH).
     * 
     * @return The value of the SH statistic.
     */
    double getMaxSH() const;

    /**
     * @brief Gets the value of the negative anomaly CUSUM statistic (SL).
     * 
     * @return The value of the SL statistic.
     */
    double getMaxSL() const;

    /**
     * @brief Gets the current value of the positive anomaly CUSUM statistic (SH).
     * 
     * @return The current value of the SH statistic.
     */
    double getSH() const;

    /**
     * @brief Gets the current value of the negative anomaly CUSUM statistic (SL).
     * 
     * @return The current value of the SL statistic.
     */
    double getSL() const;

    /**
     * @brief Gets the current mean of the observations.
     * 
     * @return The current mean.
     */
    double getMean() const;

    /**
     * @brief Gets the current variance of the observations.
     * 
     * @return The current variance.
     */
    double getVariance() const;

    /**
     * @brief Sets the threshold for detecting positive anomalies.
     * 
     * @param threshold The threshold value.
     */
    void setThresholdHigh(double threshold);

    /**
     * @brief Sets the threshold for detecting negative anomalies.
     * 
     * @param threshold The threshold value.
     */
    void setThresholdLow(double threshold);

    /**
     * @brief Gets the threshold for detecting positive anomalies.
     * 
     * @return The threshold value.
     */
    double getThresholdHigh() const;

    /**
     * @brief Gets the threshold for detecting negative anomalies.
     * 
     * @return The threshold value.
     */
    double getThresholdLow() const;

    /**
     * @brief Checks if the current observation indicates a positive anomaly.
     * 
     * @param multiplier The multiplier for the threshold.
     * @return True if the observation is a positive anomaly, false otherwise.
     */
    bool isPositiveAnomaly(double multiplier) const;

    /**
     * @brief Checks if the current observation indicates a negative anomaly.
     * 
     * @param multiplier The multiplier for the threshold.
     * @return True if the observation is a negative anomaly, false otherwise.
     */
    bool isNegativeAnomaly(double multiplier) const;

    /**
     * @brief Gets the ID of the current observation window.
     * 
     * @return The window ID.
     */
    uint32_t getWindowID() const;

    /**
     * @brief Gets the timestamp of the last alert.
     * 
     * @return The timestamp of the last alert.
     */
    timePoint getLastAlert() const;

    /**
     * @brief Sets the timestamp of the last alert.
     * 
     * @param alertTime The timestamp of the last alert.
     */
    void setLastAlert(timePoint alertTime); 

private:
    double c;           // Model parameter
    double alpha;       // Smoothing factor for EWMA of the mean
    double m;           // Long-term average
    double v;           // Standard deviation
    double SH;          // CUSUM statistic detecting positive anomaly
    double SL;          // CUSUM statistic detecting negative anomaly
    bool first;
    uint32_t span_;
    double thresholdHigh;
    double thresholdLow;
    double maxSH;
    double maxSL;
    uint32_t windowID;
    timePoint lastAlert;
};


