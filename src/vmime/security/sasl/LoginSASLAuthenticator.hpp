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

#ifndef VMIME_SECURITY_SASL_LOGINSASLAUTHENTICATOR_HPP_INCLUDED
#define VMIME_SECURITY_SASL_LOGINSASLAUTHENTICATOR_HPP_INCLUDED


#include "vmime/config.hpp"

#include "vmime/security/sasl/defaultSASLAuthenticator.hpp"

namespace vmime {
namespace security {
namespace sasl {

        /** An authenticator that is capable of providing information
         * for login authentication mechanism (username and password in base64).
         */
        class VMIME_EXPORT LoginSASLAuthenticator : public defaultSASLAuthenticator {

        public:

            LoginSASLAuthenticator();
            ~LoginSASLAuthenticator();

            const std::vector <shared_ptr <SASLMechanism> > getAcceptableMechanisms(
                    const std::vector <shared_ptr <SASLMechanism> >& available,
                    const shared_ptr <SASLMechanism>& suggested
            ) const;
        };
} // sasl
} // security
} // vmime



#endif //VMIME_SECURITY_SASL_LOGINSASLAUTHENTICATOR_HPP_INCLUDED
