//
// VMime library (http://www.vmime.org)
// Copyright (C) 2002-2005 Vincent Richard <vincent@vincent-richard.net>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 2 of
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

#include "vmime/net/smtp/SMTPResponse.hpp"

#include "vmime/platformDependant.hpp"
#include "vmime/utility/stringUtils.hpp"

#include "vmime/net/socket.hpp"
#include "vmime/net/timeoutHandler.hpp"


namespace vmime {
namespace net {
namespace smtp {


SMTPResponse::SMTPResponse(ref <socket> sok, ref <timeoutHandler> toh)
	: m_socket(sok), m_timeoutHandler(toh),
	  m_responseContinues(false)
{
}


SMTPResponse::SMTPResponse(const SMTPResponse&)
	: vmime::object()
{
	// Not used
}


const int SMTPResponse::getCode() const
{
	const int firstCode = m_lines[0].getCode();

	for (unsigned int i = 1 ; i < m_lines.size() ; ++i)
	{
		// All response codes returned must be equal
		// or else this in an error...
		if (m_lines[i].getCode() != firstCode)
			return 0;
	}

	return firstCode;
}


const string SMTPResponse::getText() const
{
	string text = m_lines[0].getText();

	for (unsigned int i = 1 ; i < m_lines.size() ; ++i)
	{
		text += '\n';
		text += m_lines[i].getText();
	}

	return text;
}


// static
ref <SMTPResponse> SMTPResponse::readResponse
	(ref <socket> sok, ref <timeoutHandler> toh)
{
	ref <SMTPResponse> resp = vmime::create <SMTPResponse>(sok, toh);

	resp->readResponse();

	return resp;
}


void SMTPResponse::readResponse()
{
	responseLine line = getNextResponse();
	m_lines.push_back(line);

	while (m_responseContinues)
	{
		line = getNextResponse();
		m_lines.push_back(line);
	}
}


const string SMTPResponse::readResponseLine()
{
	string currentBuffer = m_responseBuffer;

	while (true)
	{
		// Get a line from the response buffer
		string::size_type lineEnd = currentBuffer.find_first_of('\n');

		if (lineEnd != string::npos)
		{
			const string line(currentBuffer.begin(), currentBuffer.begin() + lineEnd);

			currentBuffer.erase(currentBuffer.begin(), currentBuffer.begin() + lineEnd + 1);
			m_responseBuffer = currentBuffer;

			return line;
		}

		// Check whether the time-out delay is elapsed
		if (m_timeoutHandler && m_timeoutHandler->isTimeOut())
		{
			if (!m_timeoutHandler->handleTimeOut())
				throw exceptions::operation_timed_out();

			m_timeoutHandler->resetTimeOut();
		}

		// Receive data from the socket
		string receiveBuffer;
		m_socket->receive(receiveBuffer);

		if (receiveBuffer.empty())   // buffer is empty
		{
			platformDependant::getHandler()->wait();
			continue;
		}

		currentBuffer += receiveBuffer;
	}
}


const SMTPResponse::responseLine SMTPResponse::getNextResponse()
{
	string line = readResponseLine();

	// Special case where CRLF occurs after response code
	if (line.length() < 4)
		line = line + '\n' + readResponseLine();

	const int code = extractResponseCode(line);
	string text;

	m_responseContinues = (line.length() >= 4 && line[3] == '-');

	if (line.length() > 4)
		text = utility::stringUtils::trim(line.substr(4));
	else
		text = utility::stringUtils::trim(line);

	return responseLine(code, text);
}


// static
const int SMTPResponse::extractResponseCode(const string& response)
{
	int code = 0;

	if (response.length() >= 3)
	{
		code = (response[0] - '0') * 100
		     + (response[1] - '0') * 10
		     + (response[2] - '0');
	}

	return code;
}


const SMTPResponse::responseLine SMTPResponse::getLineAt(const unsigned int pos) const
{
	return m_lines[pos];
}


const unsigned int SMTPResponse::getLineCount() const
{
	return m_lines.size();
}


const SMTPResponse::responseLine SMTPResponse::getLastLine() const
{
	return m_lines[m_lines.size() - 1];
}



// SMTPResponse::responseLine

SMTPResponse::responseLine::responseLine(const int code, const string& text)
	: m_code(code), m_text(text)
{
}


void SMTPResponse::responseLine::setCode(const int code)
{
	m_code = code;
}


const int SMTPResponse::responseLine::getCode() const
{
	return m_code;
}


void SMTPResponse::responseLine::setText(const string& text)
{
	m_text = text;
}


const string SMTPResponse::responseLine::getText() const
{
	return m_text;
}


} // smtp
} // net
} // vmime

