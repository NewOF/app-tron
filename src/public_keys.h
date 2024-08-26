/*******************************************************************************
 *   Ledger Ethereum App
 *   (c) 2016-2019 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#pragma once
#include <stdint.h>

static const uint8_t LEDGER_SIGNATURE_PUBLIC_KEY[] = {
#if defined(HAVE_CAL_TEST_KEY)
    0x04, 0x4c, 0xca, 0x8f, 0xad, 0x49, 0x6a, 0xa5, 0x04, 0x0a, 0x00, 0xa7, 0xeb, 0x2f,
    0x5c, 0xc3, 0xb8, 0x53, 0x76, 0xd8, 0x8b, 0xa1, 0x47, 0xa7, 0xd7, 0x05, 0x4a, 0x99,
    0xc6, 0x40, 0x56, 0x18, 0x87, 0xfe, 0x17, 0xa0, 0x96, 0xe3, 0x6c, 0x3b, 0x52, 0x3b,
    0x24, 0x4f, 0x3e, 0x2f, 0xf7, 0xf8, 0x40, 0xae, 0x26, 0xc4, 0xe7, 0x7a, 0xd3, 0xbc,
    0x73, 0x9a, 0xf5, 0xde, 0x6f, 0x2d, 0x77, 0xa7, 0xb6
#elif defined(HAVE_CAL_STAGING_KEY)
    // staging key 2019-01-11 03:07PM (trc20signer)
    0x04, 0x20, 0xda, 0x62, 0x00, 0x3c, 0x0c, 0xe0, 0x97, 0xe3, 0x36, 0x44, 0xa1, 0x0f,
    0xe4, 0xc3, 0x04, 0x54, 0x06, 0x9a, 0x44, 0x54, 0xf0, 0xfa, 0x9d, 0x4e, 0x84, 0xf4,
    0x50, 0x91, 0x42, 0x9b, 0x52, 0x20, 0xaf, 0x9e, 0x35, 0xc0, 0xb2, 0xd9, 0x28, 0x93,
    0x80, 0x13, 0x73, 0x07, 0xde, 0x4d, 0xd1, 0xd4, 0x18, 0x42, 0x8c, 0xf2, 0x1a, 0x93,
    0xb3, 0x35, 0x61, 0xbb, 0x09, 0xd8, 0x8f, 0xe5, 0x79
#else
    // production key 2019-01-11 03:07PM (trc20signer)
    0x04, 0x5e, 0x6c, 0x10, 0x20, 0xc1, 0x4d, 0xc4, 0x64, 0x42, 0xfe, 0x89, 0xf9, 0x7c,
    0x0b, 0x68, 0xcd, 0xb1, 0x59, 0x76, 0xdc, 0x24, 0xf2, 0x4c, 0x31, 0x6e, 0x7b, 0x30,
    0xfe, 0x4e, 0x8c, 0xc7, 0x6b, 0x14, 0x89, 0x15, 0x0c, 0x21, 0x51, 0x4e, 0xbf, 0x44,
    0x0f, 0xf5, 0xde, 0xa5, 0x39, 0x3d, 0x83, 0xde, 0x53, 0x58, 0xcd, 0x09, 0x8f, 0xce,
    0x8f, 0xd0, 0xf8, 0x1d, 0xaa, 0x94, 0x97, 0x91, 0x83
#endif
};

static const uint8_t LEDGER_NFT_METADATA_PUBLIC_KEY[] = {
#if defined(HAVE_NFT_TEST_KEY)
    0x04, 0x3c, 0xfb, 0x5f, 0xb3, 0x19, 0x05, 0xf4, 0xbd, 0x39, 0xd9, 0xd5, 0x35, 0xa4,
    0x0c, 0x26, 0xaa, 0xb5, 0x1c, 0x5d, 0x7d, 0x32, 0x19, 0xb2, 0x8a, 0xc9, 0x42, 0xb9,
    0x80, 0xfb, 0x20, 0x6c, 0xfb, 0x30, 0xb5, 0x1c, 0xc2, 0xde, 0x21, 0x19, 0xac, 0x03,
    0x8e, 0xbb, 0x0d, 0x7d, 0xd6, 0x54, 0x17, 0x70, 0x20, 0x4a, 0x3c, 0xed, 0x3a, 0x79,
    0xe2, 0x8b, 0x32, 0xfb, 0xb6, 0x72, 0x64, 0x68, 0xc0
#elif defined(HAVE_NFT_STAGING_KEY)
    0x04, 0xf5, 0x70, 0x0c, 0xa1, 0xe8, 0x74, 0x24, 0xc7, 0xc7, 0xd1, 0x19, 0xe7, 0xe3,
    0xc1, 0x89, 0xb1, 0x62, 0x50, 0x94, 0xdb, 0x6e, 0xa0, 0x40, 0x87, 0xc8, 0x30, 0x00,
    0x7d, 0x0b, 0x46, 0x9a, 0x53, 0x11, 0xee, 0x6a, 0x1a, 0xcd, 0x1d, 0xa5, 0xaa, 0xb0,
    0xf5, 0xc6, 0xdf, 0x13, 0x15, 0x8d, 0x28, 0xcc, 0x12, 0xd1, 0xdd, 0xa6, 0xec, 0xe9,
    0x46, 0xb8, 0x9d, 0x5c, 0x05, 0x49, 0x92, 0x59, 0xc4
#else  // production key
    0x04, 0x98, 0x8d, 0xa6, 0xb2, 0x46, 0xf2, 0x8e, 0x77, 0xc1, 0xba, 0xb6, 0x75, 0xcb,
    0x2a, 0x27, 0x44, 0xf7, 0xf5, 0xce, 0xc5, 0x6a, 0xe6, 0xe0, 0x32, 0x23, 0x33, 0x7b,
    0x57, 0x94, 0xcd, 0x6a, 0xe0, 0x7d, 0x48, 0xb3, 0x0d, 0xb9, 0xcc, 0xb4, 0x0f, 0x5a,
    0x02, 0xa1, 0x1a, 0x3a, 0xb9, 0x9d, 0x5f, 0x59, 0x5a, 0x3d, 0x50, 0xa0, 0xe1, 0x30,
    0x23, 0xfd, 0x0d, 0x95, 0x87, 0x92, 0xd7, 0x97, 0x01
#endif
};

static const uint8_t DOMAIN_NAME_PUB_KEY[] = {
#ifdef HAVE_DOMAIN_NAME_TEST_KEY
    0x04, 0xb9, 0x1f, 0xbe, 0xc1, 0x73, 0xe3, 0xba, 0x4a, 0x71, 0x4e, 0x01, 0x4e, 0xbc,
    0x82, 0x7b, 0x6f, 0x89, 0x9a, 0x9f, 0xa7, 0xf4, 0xac, 0x76, 0x9c, 0xde, 0x28, 0x43,
    0x17, 0xa0, 0x0f, 0x4f, 0x65, 0x0f, 0x09, 0xf0, 0x9a, 0xa4, 0xff, 0x5a, 0x31, 0x76,
    0x02, 0x55, 0xfe, 0x5d, 0xfc, 0x81, 0x13, 0x29, 0xb3, 0xb5, 0x0b, 0xe9, 0x91, 0x94,
    0xfc, 0xa1, 0x16, 0x19, 0xe6, 0x5f, 0x2e, 0xdf, 0xea
#else
    0x04, 0x6a, 0x94, 0xe7, 0xa4, 0x2c, 0xd0, 0xc3, 0x3f, 0xdf, 0x44, 0x0c, 0x8e, 0x2a,
    0xb2, 0x54, 0x2c, 0xef, 0xbe, 0x5d, 0xb7, 0xaa, 0x0b, 0x93, 0xa9, 0xfc, 0x81, 0x4b,
    0x9a, 0xcf, 0xa7, 0x5e, 0xb4, 0xe5, 0x3d, 0x6f, 0x00, 0x25, 0x94, 0xbd, 0xb6, 0x05,
    0xd9, 0xb5, 0xbd, 0xa9, 0xfa, 0x4b, 0x4b, 0xf3, 0xa5, 0x49, 0x6f, 0xd3, 0x16, 0x4b,
    0xae, 0xf5, 0xaf, 0xcf, 0x90, 0xe8, 0x40, 0x88, 0x71
#endif
};

// Only used for signing NFT plugins (TRC721 and TRC1155)
static const uint8_t LEDGER_NFT_SELECTOR_PUBLIC_KEY[] = {
#if defined(HAVE_SET_PLUGIN_TEST_KEY)
    0x04, 0xc0, 0x55, 0xbc, 0x4e, 0xcf, 0x05, 0x5e, 0x2d, 0x85, 0x08, 0x5d, 0x35, 0x12,
    0x7a, 0x3d, 0xe6, 0x70, 0x5c, 0x7f, 0x88, 0x50, 0x55, 0xcd, 0x70, 0x71, 0xe8, 0x76,
    0x71, 0xbf, 0x19, 0x1f, 0xe3, 0x3c, 0xc8, 0xf0, 0x1a, 0xbc, 0x2f, 0x28, 0x7c, 0x81,
    0x9a, 0x14, 0x8a, 0xbe, 0x1b, 0x58, 0x1d, 0xf1, 0xb4, 0x94, 0x0a, 0xf5, 0xd4, 0xdc,
    0x3a, 0x4e, 0x6b, 0x60, 0x19, 0x17, 0x71, 0x2b, 0x37
#elif defined(HAVE_NFT_STAGING_KEY)
    0x04, 0xf5, 0x70, 0x0c, 0xa1, 0xe8, 0x74, 0x24, 0xc7, 0xc7, 0xd1, 0x19, 0xe7, 0xe3,
    0xc1, 0x89, 0xb1, 0x62, 0x50, 0x94, 0xdb, 0x6e, 0xa0, 0x40, 0x87, 0xc8, 0x30, 0x00,
    0x7d, 0x0b, 0x46, 0x9a, 0x53, 0x11, 0xee, 0x6a, 0x1a, 0xcd, 0x1d, 0xa5, 0xaa, 0xb0,
    0xf5, 0xc6, 0xdf, 0x13, 0x15, 0x8d, 0x28, 0xcc, 0x12, 0xd1, 0xdd, 0xa6, 0xec, 0xe9,
    0x46, 0xb8, 0x9d, 0x5c, 0x05, 0x49, 0x92, 0x59, 0xc4
#else
    0x04, 0xd8, 0x62, 0x6e, 0x01, 0x9e, 0x55, 0x3e, 0x19, 0x69, 0x56, 0xf1, 0x17, 0x4d,
    0xcd, 0xb8, 0x9a, 0x1c, 0xda, 0xc4, 0x93, 0x90, 0x08, 0xbc, 0x79, 0x77, 0x33, 0x6d,
    0x78, 0x24, 0xee, 0xe3, 0xa2, 0x62, 0x24, 0x1a, 0x62, 0x73, 0x52, 0x3b, 0x09, 0xb8,
    0xd0, 0xce, 0x0d, 0x39, 0xe8, 0x60, 0xc9, 0x4d, 0x02, 0x53, 0x58, 0xdb, 0xdc, 0x25,
    0x92, 0xc7, 0xc6, 0x48, 0x0d, 0x39, 0xce, 0xbb, 0xa3
#endif
};

extern int check_signature_with_pubkey(const char *tag,
                                       uint8_t *buffer,
                                       const uint8_t bufLen,
                                       const uint8_t *PubKey,
                                       const uint8_t keyLen,
#ifdef HAVE_LEDGER_PKI
                                       const uint8_t keyUsageExp,
#endif
                                       uint8_t *signature,
                                       const uint8_t sigLen);
