
/**
 * @file binCountSketchValue.tpp
 * @brief This file contains the definition of the binCountSketchValue class, which implements BC-sketch algorithm.
 * @author Mikuláš Brázda
 * @date 15.05.2024
 */

#include "binCountSketchValue.h"

template<int noBits>
binCountSketchValue<noBits>::binCountSketchValue(u_int32_t initialValue) : totalCount(initialValue) {
    for (int i = 0; i < noBits; ++i) {
        binCount[i] = initialValue;
    }
}

template<int noBits>
u_int32_t binCountSketchValue<noBits>::getTotalCount() const {
    return totalCount;
}

template<int noBits>
binCountSketchValue<noBits>::Key binCountSketchValue<noBits>::reverseKey() const {
    Key reversed = 0;
    for (int i = 0; i < noBits; ++i) {
        if (binCount[i] > totalCount / 2) {
            reversed |= (1 << i);
        }
    }
    return reversed;
}

template<int noBits>
void binCountSketchValue<noBits>::update(const Key& key, uint16_t value) {
    totalCount += value;
    for (int i = 0; i < noBits; ++i) {
        if (key[i]) {
            binCount[i] += value;
        }
    }
}

template<int noBits>
binCountSketchValue<noBits>& binCountSketchValue<noBits>::operator-=(const binCountSketchValue<noBits>& other) {
    totalCount = totalCount < other.totalCount ? 0 : totalCount - other.totalCount;
    for (int i = 0; i < noBits; ++i) {
        binCount[i] = binCount[i] < other.binCount[i] ? 0 : binCount[i] - other.binCount[i];
    }
    return *this;
}
template<int noBits>
binCountSketchValue<noBits>& binCountSketchValue<noBits>::operator+=(const binCountSketchValue<noBits>& other) {
    totalCount += other.totalCount;
    for (int i = 0; i < noBits; ++i) {
        binCount[i] += other.binCount[i];
    }
    return *this;
}


