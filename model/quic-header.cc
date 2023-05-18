/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *
 */

#include "quic-header.h"

#include "ns3/address-utils.h"
#include "ns3/buffer.h"
#include "ns3/log.h"

#include <iostream>
#include <stdint.h>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QuicHeader");

NS_OBJECT_ENSURE_REGISTERED(QuicHeader);

QuicHeader::QuicHeader()
    : m_form(SHORT),
      m_fixed(1),

      m_type(0), // LONG HEADER ONLY

      m_s(SPIN_ZERO),  // SHORT HEADER ONLY
      m_k(PHASE_ZERO), // SHORT HEADER ONLY

      m_packetLength(0), // SHORT HEADER ONLY, 'PP' Field in Flags

      m_version(0), // LONG HEADER ONLY

      m_DCIDLength(0),
      m_connectionId(0), // = DCID

      m_SCIDLength(0),
      m_SCID(0), // LONG HEADER ONLY

      m_packetNumber(0),
      m_c(false) // (Deprecated)(Short header에서만) DCID가 있는지 없는지
{
}

QuicHeader::~QuicHeader()
{
}

std::string
QuicHeader::TypeToString() const
{
    static const char* longTypeNames[6] =
        {"Initial", "0-RTT Protected", "Handshake", "Retry", "Version Negotiation", "None"};
    static const char* shortTypeNames[4] = {"1 Octet", "2 Octets", "4 Octets"};

    std::string typeDescription = "";

    if (IsLong())
    {
        typeDescription.append(longTypeNames[m_type]);
    }
    else
    {
        typeDescription.append(shortTypeNames[m_packetLength]);
    }
    return typeDescription;
}

TypeId
QuicHeader::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::QuicHeader")
                            .SetParent<Header>()
                            .SetGroupName("Internet")
                            .AddConstructor<QuicHeader>();
    return tid;
}

TypeId
QuicHeader::GetInstanceTypeId(void) const
{
    return GetTypeId();
}

uint32_t
QuicHeader::GetSerializedSize(void) const
{
    NS_ASSERT(m_type != NONE or m_form == SHORT);

    uint32_t serializesSize = CalculateHeaderLength();
    NS_LOG_INFO("Serialized Size " << serializesSize);

    return serializesSize;
}

uint32_t
QuicHeader::CalculateHeaderLength() const
{
    uint32_t len;

    if (IsLong())
    {
        len = 8 + 32 + 8 + 8 + GetDCIDLen() +
              GetSCIDLen(); // Flags + Version + DCID Length + SCID Length + DCID + SCID
    }
    else
    {
        len = 8 + 160 * HasConnectionId() + GetPacketNumLen(); // Flags + DCID + Packet Number
                                                               // DCID 최대 길이 160비트

        // TODO: HasConnectionId 수정 (m_c 사용 X)
    }
    return len / 8;
}

uint32_t
QuicHeader::GetPacketNumLen() const
{
    if (IsLong())
    {
        return 32;
    }
    else
    {
        switch (m_packetLength)
        {
        case ONE_OCTECT: {
            return 8;
            break;
        }
        case TWO_OCTECTS: {
            return 16;
            break;
        }
        case FOUR_OCTECTS: {
            return 32;
            break;
        }
        }
    }
    NS_FATAL_ERROR("Invalid conditions");
    return 0;
}

void
QuicHeader::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this);
    NS_ASSERT(m_type != NONE or m_form == SHORT); // Short Header가 아닌데 NONE이면 에러
    NS_LOG_INFO("Serialize::Serialized Size " << CalculateHeaderLength());

    Buffer::Iterator i = start;

    uint8_t t = (m_form << 7) + (m_fixed << 6);

    // F1......

    if (m_form) // LONG Header
    {
        t += (m_type << 4); // 11TTXXXX
        i.WriteU8(t);
        i.WriteHtonU32(m_version);

        i.WriteU8(m_DCIDLength);
        i.WriteHtonU64(m_connectionId); // TODO: 가변길이로 수정

        i.WriteU8(m_SCIDLength);
        i.WriteHtonU64(m_SCID);

        if (!IsVersionNegotiation())
        {
            i.WriteHtonU32(m_packetNumber.GetValue()); // Long header에서의 패킷 번호 필드는 ?
        }
    }
    else
    {
        t += (m_s << 5) + (m_k << 2) + m_packetLength; // 01SRRKPP
        i.WriteU8(t);

        if (HasConnectionId())
        {
            i.WriteHtonU64(m_connectionId); // Little endian -> Big endian
        }

        switch (m_packetLength)
        {
        case ONE_OCTECT:
            i.WriteU8((uint8_t)m_packetNumber.GetValue());
            break;
        case TWO_OCTECTS:
            i.WriteHtonU16((uint16_t)m_packetNumber.GetValue());
            break;
        case FOUR_OCTECTS:
            i.WriteHtonU32((uint32_t)m_packetNumber.GetValue());
            break;
        }
    }
}

uint32_t
QuicHeader::Deserialize(Buffer::Iterator start)
{
    NS_LOG_FUNCTION(this);

    Buffer::Iterator i = start;

    uint8_t t = i.ReadU8(); // flags

    m_form = (t & 0x80) >> 7;

    if (IsShort())
    {
        m_s = (t & 0x20) >> 5;
        m_k = (t & 0x04) >> 2;
        // SetType (t & 0x1F); // 00011111 & 01SRRKPP
    }
    else
    {
        SetType((t & 0x30) >> 4); // 00110000 & 11TTXXXX -> m_type = 00TT0000
    }
    NS_ASSERT(m_type != NONE or m_form == SHORT);

    if (HasConnectionId())
    {
        SetConnectionID(i.ReadNtohU64()); // TODO
    }

    if (IsLong())
    {
        SetVersion(i.ReadNtohU32()); // Version Field 읽음
        if (!IsVersionNegotiation())
        {
            SetPacketNumber(SequenceNumber32(
                i.ReadNtohU32())); // TODO: Long Heade에서의 Packet Number 필드 확인
        }
    }
    else
    {
        switch (m_packetLength)
        {
        case ONE_OCTECT:
            SetPacketNumber(SequenceNumber32(i.ReadU8()));
            break;
        case TWO_OCTECTS:
            SetPacketNumber(SequenceNumber32(i.ReadNtohU16()));
            break;
        case FOUR_OCTECTS:
            SetPacketNumber(SequenceNumber32(i.ReadNtohU32()));
            break;
        }
    }

    NS_LOG_INFO("Deserialize::Serialized Size " << CalculateHeaderLength());

    return GetSerializedSize();
}

void
QuicHeader::Print(std::ostream& os) const
{
    NS_ASSERT(m_type != NONE or m_form == SHORT);

    os << "|" << m_form << "|";

    if (IsShort())
    {
        os << m_c << "|" << m_k << "|"
           << "1|0|";
    }

    os << TypeToString() << "|\n|";

    if (HasConnectionId())
    {
        os << "ConnectionID " << m_connectionId << "|\n|";
    }
    if (IsShort())
    {
        os << "PacketNumber " << m_packetNumber << "|\n";
    }
    else
    {
        os << "Version " << (uint64_t)m_version << "|\n";
        os << "PacketNumber " << m_packetNumber << "|\n|";
    }
}

QuicHeader
QuicHeader::CreateInitial(uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
    NS_LOG_INFO("Create Initial Helper called");

    QuicHeader head;
    head.SetFormat(QuicHeader::LONG);
    head.SetType(QuicHeader::INITIAL);
    head.SetConnectionID(connectionId);
    head.SetVersion(version);
    head.SetPacketNumber(packetNumber);

    return head;
}

QuicHeader
QuicHeader::CreateRetry(uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
    NS_LOG_INFO("Create Retry Helper called");

    QuicHeader head;
    head.SetFormat(QuicHeader::LONG);
    head.SetType(QuicHeader::RETRY);
    head.SetConnectionID(connectionId);
    head.SetVersion(version);
    head.SetPacketNumber(packetNumber);

    return head;
}

QuicHeader
QuicHeader::CreateHandshake(uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
    NS_LOG_INFO("Create Handshake Helper called ");

    QuicHeader head;
    head.SetFormat(QuicHeader::LONG);
    head.SetType(QuicHeader::HANDSHAKE);
    head.SetConnectionID(connectionId);
    head.SetVersion(version);
    head.SetPacketNumber(packetNumber);

    return head;
}

QuicHeader
QuicHeader::Create0RTT(uint64_t connectionId, uint32_t version, SequenceNumber32 packetNumber)
{
    NS_LOG_INFO("Create 0RTT Helper called");

    QuicHeader head;
    head.SetFormat(QuicHeader::LONG);
    head.SetType(QuicHeader::ZRTT_PROTECTED);
    head.SetConnectionID(connectionId);
    head.SetVersion(version);
    head.SetPacketNumber(packetNumber);

    return head;
}

QuicHeader
QuicHeader::CreateShort(uint64_t connectionId,
                        SequenceNumber32 packetNumber,
                        bool connectionIdFlag,
                        bool keyPhaseBit,
                        bool spinBit)
{
    NS_LOG_INFO("Create Short Helper called");

    QuicHeader head;
    head.SetFormat(QuicHeader::SHORT);
    head.SetSpinBit(spinBit);
    head.SetKeyPhaseBit(keyPhaseBit);
    head.SetPacketNumber(packetNumber);

    if (connectionIdFlag)
    {
        head.SetConnectionID(connectionId);
    }

    return head;
}

QuicHeader
QuicHeader::CreateVersionNegotiation(uint64_t connectionId,
                                     uint32_t version,
                                     std::vector<uint32_t>& supportedVersions)
{
    NS_LOG_INFO("Create Version Negotiation Helper called");

    QuicHeader head;
    head.SetFormat(QuicHeader::LONG);
    // head.SetType (QuicHeader::VERSION_NEGOTIATION);
    head.SetConnectionID(connectionId);
    head.SetVersion(0);

    //	TODO: SetVersions(m)
    //	head.SetVersions(m_supportedVersions);
    //
    //   uint8_t *buffer = new uint8_t[4 * m_supportedVersions.size()];
    //
    //    for (uint8_t i = 0; i < (uint8_t) m_supportedVersions.size(); i++) {
    //
    //	    buffer[4*i] = (m_supportedVersions[i]) ;
    //	    buffer[4*i+1] = (m_supportedVersions[i] >> 8);
    //	    buffer[4*i+2] = (m_supportedVersions[i] >> 16);
    //	    buffer[4*i+3] = (m_supportedVersions[i] >> 24);
    //
    //    }
    //
    //    Ptr<Packet> payload = Create<Packet> (buffer, 4 * m_supportedVersions.size());

    return head;
}

uint8_t
QuicHeader::GetTypeByte() const
{
    return m_type;
}

void
QuicHeader::SetType(uint8_t typeByte)
{
    m_type = typeByte;
}

void
QuicHeader::SetPacketLength(uint8_t packetLength)
{
    m_packetLength = packetLength;
}

uint8_t
QuicHeader::GetFormat() const
{
    return m_form;
}

void
QuicHeader::SetFormat(bool form)
{
    m_form = form;
}

uint8_t
QuicHeader::GetDCIDLen() const
{
    return m_DCIDLength;
}

uint8_t
QuicHeader::GetSCIDLen() const
{
    return m_SCIDLength;
}

uint64_t
QuicHeader::GetConnectionId() const
{
    NS_ASSERT(HasConnectionId());
    return m_connectionId;
}

void
QuicHeader::SetConnectionID(uint64_t connID)
{
    m_connectionId = connID;
    if (IsShort())
    {
        m_c = true;
    }
}

SequenceNumber32
QuicHeader::GetPacketNumber() const
{
    return m_packetNumber;
}

void
QuicHeader::SetPacketNumber(SequenceNumber32 packNum)
{
    NS_LOG_INFO(packNum);
    m_packetNumber = packNum;
    if (IsShort())
    {
        if (packNum.GetValue() < 256)
        {
            SetPacketLength(ONE_OCTECT);
        }
        else if (packNum.GetValue() < 65536)
        {
            SetPacketLength(TWO_OCTECTS);
        }
        else
        {
            SetPacketLength(FOUR_OCTECTS);
        }
    }
}

uint32_t
QuicHeader::GetVersion() const
{
    NS_ASSERT(HasVersion());
    return m_version;
}

void
QuicHeader::SetVersion(uint32_t version)
{
    NS_ASSERT(HasVersion());
    m_version = version;
}

bool
QuicHeader::GetKeyPhaseBit() const
{
    NS_ASSERT(IsShort());
    return m_k;
}

bool
QuicHeader::GetSpinBit() const
{
    NS_ASSERT(IsShort());
    return m_s;
}

void
QuicHeader::SetSpinBit(bool spinBit)
{
    NS_ASSERT(IsShort());
    m_s = spinBit;
}

void
QuicHeader::SetKeyPhaseBit(bool keyPhaseBit)
{
    NS_ASSERT(IsShort());
    m_k = keyPhaseBit;
}

void
QuicHeader::SetKeyPhaseBit(bool keyPhaseBit)
{
    NS_ASSERT(IsShort());
    m_k = keyPhaseBit;
}

bool
QuicHeader::IsShort() const
{
    return m_form == SHORT;
}

bool
QuicHeader::IsVersionNegotiation() const
{
    return m_version == 0;
}

bool
QuicHeader::IsInitial() const
{
    return m_type == INITIAL;
}

bool
QuicHeader::IsRetry() const
{
    return m_type == RETRY;
}

bool
QuicHeader::IsHandshake() const
{
    return m_type == HANDSHAKE;
}

bool
QuicHeader::IsORTT() const
{
    return m_type == ZRTT_PROTECTED;
}

bool
QuicHeader::HasVersion() const
{
    return IsLong();
}

bool
QuicHeader::HasConnectionId() const
{
    return not(IsShort() and m_c == false);
}

bool
operator==(const QuicHeader& lhs, const QuicHeader& rhs)
{
    if (lhs.m_form == rhs.m_form)
    {
        if (lhs.m_form)
        {
            return (
                    // && lhs.m_c == rhs.m_c
                    lhs.m_type == rhs.m_type &&
                    lhs.m_version == rhs.m_version &&
                    lhs.m_DCIDLength == rhs.m_DCIDLength &&
                    lhs.m_connectionId == rhs.m_connectionId &&
                    lhs.m_SCIDLength == rhs.m_SCIDLength &&
                    lhs.m_SCID == rhs.m_SCID &&
                    lhs.m_packetNumber == rhs.m_packetNumber); // TODO: Long header에서의 Packet Number
        }
        else {
          return (lhs.m_s == rhs.m_s
          && lhs.m_k == rhs.m_k
          && lhs.m_packetLength == rhs.m_packetLength
          && lhs.m_connectionId == rhs.m_connectionId
          && lhs.m_packetNumber == rhs.m_packetNumber
          );
        }
    }
    else return false;
}

std::ostream&
operator<<(std::ostream& os, QuicHeader& tc)
{
    tc.Print(os);
    return os;
}

} // namespace ns3
