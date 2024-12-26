/**
 * @file adaptiveCusum.cpp
 * @brief Contains the definition of the AdaptiveCUSUM class.
 * @author Mikuláš Brázda (xbrazd21@stud.fit.vutbr.cz)
 * @date 15.05.2024
 */

#include "adaptiveCusum.h"
#include <algorithm> 
#include <iostream>
#include <cmath>

AdaptiveCUSUM::AdaptiveCUSUM(double c, double alpha, uint32_t span)
        : c(c), alpha(alpha), SH(0), SL(0), first(true), thresholdHigh(0), thresholdLow(0), maxSH(0), maxSL(0), windowID(0), span_(span) {
        }

double AdaptiveCUSUM::getMaxSH() const {
    return maxSH;
}

double AdaptiveCUSUM::getMaxSL() const {
    return maxSL;
}

double AdaptiveCUSUM::getSH() const {
    return SH;
}

double AdaptiveCUSUM::getSL() const {
    return SL;
}

void AdaptiveCUSUM::setThresholdHigh(double threshold) {
    thresholdHigh = threshold;
}

void AdaptiveCUSUM::setThresholdLow(double threshold) {
    thresholdLow = threshold;
}

double AdaptiveCUSUM::getThresholdHigh() const {
    return thresholdHigh;
}

double AdaptiveCUSUM::getThresholdLow() const {
    return thresholdLow;
}

bool AdaptiveCUSUM::isPositiveAnomaly(double multiplier) const {
    return SH > (thresholdHigh * multiplier);
}

bool AdaptiveCUSUM::isNegativeAnomaly(double multiplier) const {
    return SL > (thresholdLow * multiplier);
}

double AdaptiveCUSUM::getMean() const {
    return m;
}

double AdaptiveCUSUM::getVariance() const {
    return v;
}

void AdaptiveCUSUM::setLastAlert(timePoint alertTime) {
    lastAlert = alertTime;
}

timePoint AdaptiveCUSUM::getLastAlert() const {
    return lastAlert;
}

void AdaptiveCUSUM::process(double currentValue, bool learning) {
    if (first) {
        m = currentValue;
        v = 0.0;
        first = false;
        return;
    }
    double diff = currentValue - m;
    double incr = alpha * diff;
    m += incr;
    v = (1 - alpha) * v + alpha * diff * diff;

    // Update the CUSUM statistic
    if ((not learning) or (windowID >= span_))
    {
        SH = std::max(0.0, SH + (currentValue - m) - c * std::sqrt(v));
        SL = std::max(0.0, SL - (currentValue - m) - c * std::sqrt(v));
    }
    maxSH = std::max(SH, maxSH);
    maxSL = std::max(SL, maxSL);

    windowID++;
}

uint32_t AdaptiveCUSUM::getWindowID() const {
    return windowID;
};