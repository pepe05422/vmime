//
// VMime library (http://www.vmime.org)
// Copyright (C) 2002 Vincent Richard <vincent@vmime.org>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// Linking this library statically or dynamically with other modules is making
// a combined work based on this library.  Thus, the terms and conditions of
// the GNU General Public License cover the whole combination.
//

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#include <gsasl.h>

#include "vmime/security/sasl/LoginSASLMechanism.hpp"

#include "vmime/security/sasl/SASLContext.hpp"
#include "vmime/security/sasl/SASLSession.hpp"

#include "vmime/exception.hpp"

namespace vmime {
    namespace security {
        namespace sasl {
            LoginSASLMechanism::LoginSASLMechanism(
                    const shared_ptr<SASLContext> &ctx,
                    const string &name)
                    : m_context(ctx),
                      m_complete(false)
            {}

            LoginSASLMechanism::~LoginSASLMechanism()
            {}

            const string LoginSASLMechanism::getName() const {
                return "LOGIN";
            }

            bool LoginSASLMechanism::step(
                const shared_ptr<SASLSession> &sess,
                const byte_t *challenge,
                const size_t challengeLen,
                byte_t **response,
                size_t *responseLen
            ) {
                // Encode in base64 user address and pass,
                // S: 334 VXNlcm5hbWU6 -> "Username:"
                // C: _user address encoded in base64_
                // S: 334 UGFzc3dvcmQ6 -> "Password:"
                // C: _pass encoded in base64_
                // S: 235 2.7.0 Authentication successful

                auto input = std::string(reinterpret_cast<const char *>(challenge));

                if (input == "Username:")
                {
                    const std::string user(sess->getAuthenticator()->getUsername());
                    byte_t* userResp = new byte_t[user.length()];
                    std::copy(user.c_str(), user.c_str() + user.length(), userResp);

                    *response = userResp;
                    *responseLen = user.length();
                    m_complete = false;

                    return false;
                }
                else if (input == "Password:")
                {
                    const std::string pass(sess->getAuthenticator()->getPassword());
                    byte_t* passResp = new byte_t[pass.length()];
                    std::copy(pass.c_str(), pass.c_str() + pass.length(), passResp);

                    *response = passResp;
                    *responseLen = pass.length();
                    m_complete = true;

                    return true;
                }
                else
                {
                    throw;
                }


                /*char *output = 0;
                size_t outputLen = 0;

                if (nullptr == sess->m_gsaslSession)
                {
                    throw exceptions::sasl_exception("Invalid SASL session");
                }

                const int result = gsasl_step64(
                    sess->m_gsaslSession,
                    reinterpret_cast<const char *>(challenge),
                    &output);


                if (result == GSASL_OK || result == GSASL_NEEDS_MORE)
                {
                    byte_t *res = new byte_t[outputLen];

                    for (size_t i = 0; i < outputLen; ++i)
                    {
                        res[i] = output[i];
                    }

                    *response = res;
                    *responseLen = outputLen;

                    gsasl_free(output);
                }
                else
                {
                    *response = 0;
                    *responseLen = 0;
                }

                if (result == GSASL_OK)
                {
                    // Authentication process completed
                    m_complete = true;
                    return true;
                }
                else if (result == GSASL_NEEDS_MORE)
                {
                    // Continue authentication process
                    return false;
                }
                else if (result == GSASL_MALLOC_ERROR)
                {
                    throw std::bad_alloc();
                }
                else
                {
                    throw exceptions::sasl_exception(
                        "Error when processing challenge " +
                        SASLContext::getErrorMessage(
                                "gsasl_step", result
                        )
                    );
                }*/
            }

            bool LoginSASLMechanism::isComplete() const
            {
                return m_complete;
            }

            bool LoginSASLMechanism::hasInitialResponse() const
            {
                return false;
            }

            void LoginSASLMechanism::encode(
                    const shared_ptr<SASLSession> &sess,
                    const byte_t *input,
                    const size_t inputLen,
                    byte_t **output,
                    size_t *outputLen)
            {
                // No encoding performed, just copy input bytes
                byte_t* res = new byte_t[inputLen];
                std::copy(input, input + inputLen, res);

                *outputLen = inputLen;
                *output = res;
            }

            void LoginSASLMechanism::decode(
                    const shared_ptr<SASLSession> &sess,
                    const byte_t *input,
                    const size_t inputLen,
                    byte_t **output, size_t *outputLen)
            {
                // No decoding performed, just copy input bytes
                byte_t* res = new byte_t[inputLen];
                std::copy(input, input + inputLen, res);

                *outputLen = inputLen;
                *output = res;
            }
        } // sasl
    } // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT