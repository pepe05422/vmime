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

#include "LoginSASLAuthenticator.hpp"

#include "vmime/security/sasl/SASLMechanism.hpp"
#include "vmime/security/sasl/SASLSession.hpp"
#include "vmime/security/sasl/SASLContext.hpp"

namespace vmime {
namespace security {
namespace sasl {
        LoginSASLAuthenticator::LoginSASLAuthenticator()
        {
        }

        LoginSASLAuthenticator::~LoginSASLAuthenticator()
        {
        }

        const std::vector <shared_ptr <SASLMechanism> >
        LoginSASLAuthenticator::getAcceptableMechanisms(
                const std::vector <shared_ptr <SASLMechanism> >& available,
                const shared_ptr <SASLMechanism>& suggested
        ) const {
            std::vector <shared_ptr <SASLMechanism> > mechs;

            for (size_t i = available.size() ; i != 0 ; --i) {

                shared_ptr <SASLMechanism> mech = available[i - 1];

                if ("LOGIN" == mech->getName()) {
                    // Only allow LOGIN
                    mechs.push_back(mech);
                }
            }

            return mechs;
        }
} // sasl
} // security
} // vmime