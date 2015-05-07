/*
 * TCPFit.cc
 *
 * Copyright (C) 2015 Spyridon Marinis Artelaris
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <algorithm>    // min,max
#include "inet/transportlayer/tcp/flavours/TCPFit.h"
#include "inet/transportlayer/tcp/TCP.h"

namespace inet {

    namespace tcp {

        Register_Class(TCPFit);

        TCPFitStateVariables::TCPFitStateVariables() {
            // init
            ssthresh = ULONG_MAX;
            snd_cwnd = 2;
            w_RTTmin = 0;
            RTT_cnt = 0;
            ACK_cnt = 0;
            epoch_start = simTime();
            cwnd_cnt = 0;
            n = 1;
            beta = 0;
            alpha = 1; // ???not so sure to which value we need to set it.
        }

        TCPFitStateVariables::~TCPFitStateVariables() {
        }

        std::string TCPFitStateVariables::info() const {
            std::stringstream out;
            out << TCPFitStateVariables::info();
            out << " ssthresh=" << ssthresh;
            return out.str();
        }

        std::string TCPFitStateVariables::detailedInfo() const {
            std::stringstream out;
            out << TCPFitStateVariables::detailedInfo();
            out << "ssthresh = " << ssthresh << "\n";
            out << "w_RTTmin = " << w_RTTmin << "\n";
            return out.str();
        }

        /* Ctor */
        TCPFit::TCPFit()
            : TCPBaseAlg(), state((TCPFitStateVariables *&) TCPAlgorithm::state) {
        }

        void TCPFit::recalculateSlowStartThreshold() {
            EV_DEBUG << "recalculateSlowStartThreshold(), ssthresh=" << state->ssthresh << "\n";

            // TCP-FIT packet loss
            state->ssthresh = state->snd_cwnd - ((2 * state->snd_cwnd) / 3 * (state->n + 1));
        }

        void TCPFit::processRexmitTimer(TCPEventCode& event) {
            TCPBaseAlg::processRexmitTimer(event);

            if (event == TCP_E_ABORT) {
                return;
            }

            // not sure if it should be the same as TCP Reno on retransmit.
            recalculateSlowStartThreshold();
            state->snd_cwnd = state->snd_mss;

            if (cwndVector)
                cwndVector->record(state->snd_cwnd);

            state->afterRto = true;
            conn->retransmitOneSegment(true);
        }

        void TCPFit::receivedDataAck(uint32 firstSeqAcked) {
            TCPBaseAlg::receivedDataAck(firstSeqAcked);

            if (state->dupacks >= DUPTHRESH) {    // DUPTHRESH = 3
                // TCP-Fit uses the same fast recovery as TCP Reno
                // Perform Fast Recovery: set cwnd to ssthresh (deflating the window).
                //
                EV_INFO << "Fast Recovery: setting cwnd to ssthresh=" << state->ssthresh << "\n";
                state->snd_cwnd = state->ssthresh;

                if (cwndVector)
                    cwndVector->record(state->snd_cwnd);
            }
            else {
                //
                // Perform slow start and congestion avoidance.
                //
                const TCPSegmentTransmitInfoList::Item *found = state->regions.get(firstSeqAcked);
                state->regions.clearTo(state->snd_una);

                if (found != nullptr) { // will it work?
                    simtime_t currentTime = simTime();
                    simtime_t newRTT = currentTime - found->getFirstSentTime();

                    state->RTT_cnt += newRTT;

                    if (state->w_RTTmin == 0) {
                        state->w_RTTmin = std::min(state->w_RTTmin, newRTT);
                    }
                    else {
                        state->w_RTTmin = newRTT; // or simTime() ???
                    }

                }
                state->ACK_cnt++;

                if (state->snd_cwnd <= state->ssthresh) {
                    // slow start
                    state->snd_cwnd += 1;
                }
                else {
                    // cong. avoidance
                    state->cwnd_cnt += state->n;

                    if (state->cwnd_cnt > state->snd_cwnd) {
                        state->snd_cwnd += 1;
                    }
                }

                if (cwndVector)
                    cwndVector->record(state->snd_cwnd);
            }

            TCPFit::tcpFitUpdateN();
        }

        void TCPFit::receivedDuplicateAck() { // everything like TCP Reno
            TCPBaseAlg::receivedDuplicateAck();
            if (state->dupacks == DUPTHRESH) {    // DUPTHRESH = 3
                EV_INFO << "TCP-FIT on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";

                // TCP Reno - TCP SACK removed

                // enter Fast Recovery
                recalculateSlowStartThreshold();
                // "set cwnd to ssthresh plus 3 * SMSS." (RFC 2581)
                state->snd_cwnd = state->ssthresh + 3 * state->snd_mss;    // 20051129 (1)

                if (cwndVector)
                    cwndVector->record(state->snd_cwnd);

                EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";

                // Fast Retransmission: retransmit missing segment without waiting
                // for the REXMIT timer to expire
                conn->retransmitOneSegment(false);

                // Do not restart REXMIT timer.
                // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
                // Resetting the REXMIT timer is discussed in RFC 2582/3782 (NewReno) and RFC 2988.

                // TCP Reno - TCP SACK removed

                // try to transmit new segments (RFC 2581)
                sendData(false);
            }
        }

        void TCPFit::dataSent(uint32 fromseq) {
            TCPBaseAlg::dataSent(fromseq);

            // save the time the packet was sent
            // fromseq is the seq number of the 1st sent byte

            simtime_t sendtime = simTime();
            state->regions.clearTo(state->snd_una);
            state->regions.set(fromseq, state->snd_max, sendtime);
        }

        void TCPFit::segmentRetransmitted(uint32 fromseq, uint32 toseq) {
            TCPBaseAlg::segmentRetransmitted(fromseq, toseq);

            state->regions.set(fromseq, toseq, simTime());
        }

        void TCPFit::tcpFitUpdateN() {
            currentTime = simTime();
            if (state->beta == 0) {
                if ((currentTime - state->epoch_start) > state->update_epoch) { // what is update_epoch??
                    state->epoch_start = currentTime; // instead of time_stamp ??
                    state->avgRTT = state->RTT_cnt / state->ACK_cnt;
                    double rtt_diff = SIMTIME_DBL(state->avgRTT - state->w_RTTmin);
                    int something = state->n + rtt_diff;
                    something /= std::ceil(state->avgRTT.dbl() + state->alpha);
                    state->n = std::max(1, something);
                }
            }
            else {
                if ((currentTime - state->epoch_start) > state->update_epoch) { // what is update_epoch??
                    state->epoch_start = currentTime;
                    state->avgRTT = state->RTT_cnt / state->ACK_cnt;
                    double rtt_diff = SIMTIME_DBL(state->avgRTT - state->w_RTTmin);
                    int something = state->n + state->beta - (state->beta * rtt_diff);
                    something /= std::ceil(state->avgRTT.dbl() + state->alpha);
                    state->n = std::max(1, something);
                }
            }
        }

        void TCPFit::tcpFitReset() {
            state->w_RTTmin = 0;
            state->RTT_cnt = 0;
            state->ACK_cnt = 0;
            currentTime = simTime();
            state->epoch_start = simTime();
            state->cwnd_cnt = 0;
            state->n = 1;
            state->beta = 0;
            state->alpha = 1;
        }
    } // namespace tcp
} // namespace inet
