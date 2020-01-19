#ifndef DONATE_H
#define DONATE_H

/*
 * Minimum dev donation.
 * Minimum percentage of your hashing power that you want to donate to the
 * developer, can be 0 if you prefer not to.
 * You can set the donation percentage higher by using the --donate flag.
 *
 * Example of how it works for the default setting of 1:
 * You miner will mine into your usual pool for 99 minutes, then switch to the
 * developer's pool for 1 minute.
 *
 * If you plan on changing this setting to 0 please consider making a one-time
 * donation to the developers' wallets:
 *
 * tpruvot (ccminer)
 * BTC donation address: 1AJdfCpLWPNoAMDfHF1wD5y8VgKSSTHxPo
 *
 * brianmct (x16r optimizations)
 * BTC donation address: 1FHLroBZaB74QvQW5mBmAxCNVJNXa14mH5
 * RVN donation address: RWoSZX6j6WU6SVTVq5hKmdgPmmrYE9be5R
 *
 */
#include "algos.h"

#ifndef MIN_DEV_DONATE_PERCENT

//#define MIN_DEV_DONATE_PERCENT 4.5
//#define MIN_DEV_DONATE_PERCENT 10.0
#define MIN_DEV_DONATE_PERCENT 0.0
//#define MIN_DEV_DONATE_PERCENT 1.0
//#define MIN_DEV_DONATE_PERCENT 2.5
//#define MIN_DEV_DONATE_PERCENT 8.0

//#define MIN_DEV_DONATE_PERCENT 16.0
//#define TWO_FEES 1

//#define MIN_DEV_DONATE_PERCENT 25.0

//always build 8% first, so you dont forget about having an 8% around.

#endif


#define LOCK_ALGO ALGO_EAGLE


// 100 minutes
//#define DONATE_CYCLE_TIME 6000

//10 minutes
#define DONATE_CYCLE_TIME 600

#endif
