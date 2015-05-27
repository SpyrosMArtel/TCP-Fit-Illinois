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
 *  Created on: 29 Mar 2015
 */
#include <algorithm>    // min,max
#include "inet/transportlayer/tcp/flavours/TCPFit.h"
#include "inet/transportlayer/tcp/TCP.h"

namespace inet {

    namespace tcp {

        Register_Class(TCPFit);

        TCPFitStateVariables::TCPFitStateVariables() {
            // init
            update_epoch = 0;
            ssthresh = ULONG_MAX;
            snd_cwnd = 2;
            w_RTTmin = 0x7fffffff;
            RTT_cnt = 0;
            ACK_cnt = 0;
            epoch_start = 0;
            cwnd_cnt = 0;
            n = 1;
            beta = 0;
            alpha = 1; // ???not so sure to which value we need to set it.
        }

        TCPFitStateVariables::~TCPFitStateVariables() {
        }

        std::string TCPFitStateVariables::info() const {
            std::stringstream out;
            out << TCPBaseAlgStateVariables::info();
            out << " ssthresh=" << ssthresh;
            return out.str();
        }

        std::string TCPFitStateVariables::detailedInfo() const {
            std::stringstream out;
            out << TCPBaseAlgStateVariables::detailedInfo();
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
            /* begin Slow Start (RFC 2581) */
            recalculateSlowStartThreshold();
            state->snd_cwnd = state->snd_mss;

            if (cwndVector)
                cwndVector->record(state->snd_cwnd);

            state->afterRto = true;
            conn->retransmitOneSegment(true);
        }

        void TCPFit::receivedDataAck(uint32 firstSeqAcked) {
            TCPBaseAlg::receivedDataAck(firstSeqAcked);
            const TCPSegmentTransmitInfoList::Item *found = state->regions.get(firstSeqAcked);

            if (found != nullptr) {
                simtime_t currentTime = simTime();
                simtime_t newRTT = currentTime - found->getFirstSentTime();

                state->RTT_cnt += newRTT;

                // Update RTTmin
                if (state->w_RTTmin > newRTT) {
                    state->w_RTTmin = newRTT;
                }

                /* the update period is either equal to newRTT or 500ms */
                state->update_epoch = std::max(newRTT.dbl(), 0.500);
            }

            if (state->dupacks >= DUPTHRESH) {    // DUPTHRESH = 3
                // TCP-Fit uses the same fast recovery as TCP Reno
                EV_INFO << "Fast Recovery: setting cwnd to ssthresh=" << state->ssthresh << "\n";
                state->snd_cwnd = state->ssthresh;

                if (cwndVector)
                    cwndVector->record(state->snd_cwnd);
            }
            else {
                //
                // Perform slow start and congestion avoidance.
                //
                state->ACK_cnt++;

                if (state->snd_cwnd <= state->ssthresh) {
                    // slow start
                    state->snd_cwnd++;

                    if (cwndVector) {
                        cwndVector->record(state->snd_cwnd);
                    }

                    EV_INFO << "cwnd=" << state->snd_cwnd << "\n";
                }
                else {
                    // cong. avoidance
                    state->cwnd_cnt += state->n;

                    if (state->cwnd_cnt > state->snd_cwnd) {
                        state->snd_cwnd++;
                    }
                }

                if (cwndVector)
                    cwndVector->record(state->snd_cwnd);
            }

            TCPFit::tcpFitUpdateN(); /* update N parameter */
            state->regions.clearTo(state->snd_una);
            // RFC 3517, pages 7 and 8: "5.1 Retransmission Timeouts
            sendData(false);
        }

        void TCPFit::receivedDuplicateAck() { // everything like TCP Reno
            TCPBaseAlg::receivedDuplicateAck();
            if (state->dupacks == DUPTHRESH) {    // DUPTHRESH = 3
                EV_INFO << "Reno on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";

                if (state->sack_enabled) {
                    // RFC 3517, page 6 and page 8
                    if (state->recoveryPoint == 0 || seqGE(state->snd_una, state->recoveryPoint)) {
                        state->recoveryPoint = state->snd_max;
                        state->lossRecovery = true;
                        EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
                    }
                }
                // RFC 2581, page 5:
                // enter Fast Recovery
                recalculateSlowStartThreshold();
                // "set cwnd to ssthresh plus 3 * SMSS." (RFC 2581)
                state->snd_cwnd = state->ssthresh + 3 * state->snd_mss;    // 20051129 (1)

                if (cwndVector) {
                    cwndVector->record(state->snd_cwnd);
                }

                EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";

                // Fast Retransmission: retransmit missing segment without waiting for the REXMIT timer to expire
                conn->retransmitOneSegment(false);

                if (state->sack_enabled) {
                    // RFC 3517, page 7: "(4) Run SetPipe ()
                    conn->setPipe();
                    // RFC 3517, page 7: "(5)
                    if (state->lossRecovery) {
                        // RFC 3517, page 9
                        EV_INFO << "Retransmission sent during recovery, restarting REXMIT timer.\n";
                        restartRexmitTimer();

                        // RFC 3517, page 7: "(C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
                        // segments as follows:"
                        if (((int)state->snd_cwnd - (int)state->pipe) >= (int)state->snd_mss) {
                            conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
                        }
                    }
                }

                // try to transmit new segments (RFC 2581)
                sendData(false);
            }
            else if (state->dupacks > DUPTHRESH) {    // DUPTHRESH = 3
                /*For each additional duplicate ACK received, increment cwnd by SMSS.*/
                state->snd_cwnd += state->snd_mss;
                EV_DETAIL << "Reno on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";

                if (cwndVector) {
                    cwndVector->record(state->snd_cwnd);
                }
                // Note: Steps (A) - (C) of RFC 3517, page 7 ("Once a TCP is in the loss recovery phase the following procedure MUST be used for each arriving ACK")
                // should not be used here!
                // RFC 3517, pages 7 and 8: "5.1 Retransmission Timeouts
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
                if ((currentTime - state->epoch_start) > state->update_epoch) {
                    state->epoch_start = currentTime; // instead of time_stamp ??
                    state->avgRTT = state->RTT_cnt / state->ACK_cnt;
                    double rtt_diff = SIMTIME_DBL(state->avgRTT - state->w_RTTmin);
                    double nValue = state->n + rtt_diff;
                    nValue /= state->avgRTT.dbl() + state->alpha;
                    state->n = std::max(1.0, nValue);
                }
            }
            else {
                if ((currentTime - state->epoch_start) > state->update_epoch) {
                    state->epoch_start = currentTime;
                    state->avgRTT = state->RTT_cnt / state->ACK_cnt;
                    double rtt_diff = SIMTIME_DBL(state->avgRTT - state->w_RTTmin);
                    double nValue = state->n + (state->beta - (state->beta * rtt_diff));
                    nValue /= (state->avgRTT.dbl() + state->alpha);
                    state->n = std::max(1.0, nValue);
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
