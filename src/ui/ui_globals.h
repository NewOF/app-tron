/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2022 Ledger
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
#include "../parse.h"

#define VOTE_ADDRESS 0
#ifdef HAVE_BAGL
#define VOTE_ADDRESS_SIZE 15
#else
#define VOTE_ADDRESS_SIZE BASE58CHECK_ADDRESS_SIZE + 1
#endif
#define VOTE_AMOUNT           VOTE_ADDRESS_SIZE
#define VOTE_AMOUNT_SIZE      15
#define VOTE_PACK             (VOTE_ADDRESS_SIZE + VOTE_AMOUNT_SIZE)
#define voteSlot(index, type) ((index * VOTE_PACK) + type)

extern volatile uint8_t customContractField;
extern char
    fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];  // 5 extra bytes used to inform MultSign ID
extern char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
extern char addressSummary[40];
extern char fullContract[MAX_TOKEN_LENGTH];
extern char TRC20Action[9];
extern char TRC20ActionSendAllow[8];
extern char fullHash[HASH_SIZE * 2 + 1];
extern int8_t votes_count;
extern tmpCtx_t global_ctx;
extern cx_sha3_t global_sha3;
extern strings_t strings;

bool ui_callback_tx_ok(bool display_menu);
bool ui_callback_tx_cancel(bool display_menu);
bool ui_callback_address_ok(bool display_menu);
bool ui_callback_signMessage_ok(bool display_menu);
bool ui_callback_ecdh_ok(bool display_menu);
bool ui_callback_signMessage712_v0_cancel(bool display_menu);
bool ui_callback_signMessage712_v0_ok(bool display_menu);

#define UI_191_BUFFER strings.tmp.tmp

void reset_ui_191_buffer(void);
size_t ui_191_buffer_length(void);
size_t remaining_ui_191_buffer_length(void);
char *remaining_ui_191_buffer(void);

void ui_191_start(void);
void ui_191_switch_to_message(void);
void ui_191_switch_to_message_end(void);
void ui_191_switch_to_sign(void);
void ui_191_switch_to_question(void);

uint8_t feed_display(void);
void skip_rest_of_message(void);
void question_switcher(void);
void continue_displaying_message(void);

#ifdef HAVE_NBGL

#define TEXT_MESSAGE       "message"
#define TEXT_TYPED_MESSAGE "typed " TEXT_MESSAGE
#define TEXT_REVIEW_EIP712 REVIEW(TEXT_TYPED_MESSAGE)
#define TEXT_SIGN_EIP712   SIGN(TEXT_TYPED_MESSAGE)

#define SIGN_BUTTON           "Hold to sign"
#define REJECT_BUTTON         "Reject"
#define SIGN(msg)             "Sign " msg "?"
#define REVIEW(msg)           "Review " msg
#define REJECT(msg)           "Reject " msg
#define REJECT_QUESTION(msg)  REJECT(msg) "?"
#define REJECT_CONFIRM_BUTTON "Yes, reject"
#define RESUME(msg)           "Go back to " msg

typedef enum {
    UI_SIGNING_POSITION_START = 0,
    UI_SIGNING_POSITION_REVIEW,
    UI_SIGNING_POSITION_SIGN
} e_ui_signing_position;

extern e_ui_signing_position g_position;

extern char g_stax_shared_buffer[SHARED_BUFFER_SIZE];
#endif