/*
 * TCPIllinois.cc
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
#include "inet/transportlayer/tcp/flavours/TCPIllinois.h"
#include "inet/transportlayer/tcp/TCP.h"

#define ALPHA_SHIFT     7
#define ALPHA_SCALE     (1u << ALPHA_SHIFT)
#define ALPHA_MIN       ((3 * ALPHA_SCALE) / 10 ) /* ~0.3 */
#define ALPHA_MAX       ( 10 * ALPHA_SCALE ) /* 10.0 */
#define ALPHA_BASE      ALPHA_SCALE /* 1.0 */
#define RTT_MAX         (U32_MAX / ALPHA_MAX) /* 3.3 secs */

#define BETA_SHIFT      6
#define BETA_SCALE      (1u << BETA_SHIFT)
#define BETA_MIN        (BETA_SCALE / 8) /* 0.125 */
#define BETA_MAX        (BETA_SCALE / 2) /* 0.5 */
#define BETA_BASE       BETA_MAX

static int theta = 5;

namespace inet {

    namespace tcp {

        Register_Class(TCPIllinois);

        TCPIllinoisStateVariables::TCPIllinoisStateVariables() {
            // init
            ssthresh = ULONG_MAX;
            snd_cwnd_clamp = ~0; // set top limit to the maximum number allowed from an 32 bit int
            snd_cwnd = 2;
            w_RTTmin = 0x7fffffff;
            max_rtt = 0;
//            acked = 0;
            rtt_low = 0;
            rtt_above = 0;
            beta = BETA_BASE;
            alpha = ALPHA_MAX;
        }

        TCPIllinoisStateVariables::~TCPIllinoisStateVariables() {
        }

        std::string TCPIllinoisStateVariables::info() const {
            std::stringstream out;
            out << TCPIllinoisStateVariables::info();
            out << " ssthresh=" << ssthresh;
            return out.str();
        }

        std::string TCPIllinoisStateVariables::detailedInfo() const {
            std::stringstream out;
            out << TCPIllinoisStateVariables::detailedInfo();
            out << "ssthresh = " << ssthresh << "\n";
            out << "w_RTTmin = " << w_RTTmin << "\n";
            return out.str();
        }

        /* Ctor */
        TCPIllinois::TCPIllinois()
            : TCPBaseAlg(), state((TCPIllinoisStateVariables *&) TCPAlgorithm::state) {
        }

        void TCPIllinois::recalculateSlowStartThreshold() { // like TCP NewReno
            EV_DEBUG << "recalculateSlowStartThreshold(), ssthresh=" << state->ssthresh << "\n";
            // RFC 2581, page 4:
            uint32 flight_size = std::min(state->snd_cwnd, state->snd_wnd);
            // uint32 flight_size = state->snd_max - state->snd_una;
            state->ssthresh = std::max(flight_size / 2, 2 * state->snd_mss);

            if (ssthreshVector) {
                ssthreshVector->record(state->ssthresh);
            }
        }

        void TCPIllinois::processRexmitTimer(TCPEventCode& event) {
            TCPBaseAlg::processRexmitTimer(event);

            if (event == TCP_E_ABORT)
                return;

            // RFC 3782, page 6:
            // "6)  Retransmit timeouts:

/* should those be kept?
            state->recover = (state->snd_max - 1);
            EV_INFO << "recover=" << state->recover << "\n";
            state->lossRecovery = false;
            state->firstPartialACK = false;
            EV_INFO << "Loss Recovery terminated.\n";
*/

            // begin Slow Start (RFC 2581)
            recalculateSlowStartThreshold();
            state->snd_cwnd = state->snd_mss;

            if (cwndVector) {
                cwndVector->record(state->snd_cwnd);
            }

            EV_INFO << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
                    << ", ssthresh=" << state->ssthresh << "\n";
            state->afterRto = true;
            conn->retransmitOneSegment(true);
        }

        void TCPIllinois::receivedDataAck(uint32 firstSeqAcked) {
            TCPBaseAlg::receivedDataAck(firstSeqAcked);

            update_params(state);

            //
            // Perform slow start (like TCP NewReno) and congestion avoidance.
            //
            if (state->snd_cwnd <= state->ssthresh) {
                EV_DETAIL << "cwnd <= ssthresh: Slow Start: increasing cwnd by SMSS bytes to ";

                state->snd_cwnd += state->snd_mss;

                if (cwndVector) {
                    cwndVector->record(state->snd_cwnd);
                }

                EV_DETAIL << "cwnd=" << state->snd_cwnd << "\n";
            }
            else {
                uint32_t delta;
                /* snd_cwnd_cnt is # of packets since last cwnd increment */
                state->snd_cwnd_cnt++;
//                state->acked = 1; // maybe not needed ??

                /* This is close approximation of:
                 * tp->snd_cwnd += alpha/tp->snd_cwnd
                 */
                delta = (state->snd_cwnd_cnt * state->alpha) >> ALPHA_SHIFT;
                if (delta >= state->snd_cwnd) {
                    state->snd_cwnd = std::min(state->snd_cwnd + delta / state->snd_cwnd, state->snd_cwnd_clamp);
                    state->snd_cwnd_cnt = 0;
                }

                if (cwndVector) {
                    cwndVector->record(state->snd_cwnd);
                }
            }
        }

        void TCPIllinois::receivedDuplicateAck() { // like TCP NewReno impl.
            TCPBaseAlg::receivedDuplicateAck();

            if (state->dupacks == DUPTHRESH) {    // DUPTHRESH = 3
                if (!state->lossRecovery) {
                    // RFC 3782, page 4:
                    // "1) Three duplicate ACKs:
                    // When the third duplicate ACK is received and the sender is not
                    // already in the Fast Recovery procedure, check to see if the
                    // Cumulative Acknowledgement field covers more than "recover".  If
                    // so, go to Step 1A.  Otherwise, go to Step 1B."
                    //
                    // RFC 3782, page 6:
                    // "Step 1 specifies a check that the Cumulative Acknowledgement field
                    // covers more than "recover".  Because the acknowledgement field
                    // contains the sequence number that the sender next expects to receive,
                    // the acknowledgement "ack_number" covers more than "recover" when:
                    //      ack_number - 1 > recover;"
                    if (state->snd_una - 1 > state->recover) {
                        EV_INFO << "TCP Illinois on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";

                        // RFC 3782, page 4:
                        // "1A) Invoking Fast Retransmit:

                        recalculateSlowStartThreshold();
                        state->recover = (state->snd_max - 1);
                        state->firstPartialACK = false;
                        state->lossRecovery = true;
                        EV_INFO << " set recover=" << state->recover;

                        // RFC 3782, page 4:
                        // "2) Entering Fast Retransmit:
                        state->snd_cwnd = state->ssthresh + 3 * state->snd_mss;

                        if (cwndVector) {
                            cwndVector->record(state->snd_cwnd);
                        }

                        EV_DETAIL << " , cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";
                        conn->retransmitOneSegment(false);

                        // RFC 3782, page 5:
                        // "4) Fast Recovery, continued:
                        sendData(false);
                    }
                    else {
                        EV_INFO << "TCP Illinois on dupAcks == DUPTHRESH(=3): not invoking Fast Retransmit and Fast Recovery\n";
                        // RFC 3782, page 4:
                        // "1B) Not invoking Fast Retransmit:
                    }
                }
                EV_INFO << "TCP Illinois on dupAcks == DUPTHRESH(=3): TCP is already in Fast Recovery procedure\n";
            }
            else if (state->dupacks > DUPTHRESH) {    // DUPTHRESH = 3
                if (state->lossRecovery) {
                    // RFC 3782, page 4:
                    // "3) Fast Recovery:
                    state->snd_cwnd += state->snd_mss;

                    if (cwndVector)
                        cwndVector->record(state->snd_cwnd);

                    EV_DETAIL << "TCP Illinois on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";

                    // RFC 3782, page 5:
                    // "4) Fast Recovery, continued:
                    sendData(false);
                }
            }
        }

        void TCPIllinois::dataSent(uint32 fromseq) {
            TCPBaseAlg::dataSent(fromseq);

            // save the time the packet was sent
            // fromseq is the seq number of the 1st sent byte

            simtime_t sendtime = simTime();
            state->regions.clearTo(state->snd_una);
            state->regions.set(fromseq, state->snd_max, sendtime);
        }

        void TCPIllinois::segmentRetransmitted(uint32 fromseq, uint32 toseq) {
            TCPBaseAlg::segmentRetransmitted(fromseq, toseq);

            state->regions.set(fromseq, toseq, simTime());
        }

        /* Update alpha and beta values once per RTT */
        void TCPIllinois::update_params(TCPIllinoisStateVariables *& state) {
            if (state->snd_cwnd < state->ssthresh) {
                state->alpha = ALPHA_BASE;
                state->beta = BETA_BASE;
            }
            else if (state->cnt_rtt > 0) {
            	//TODO: Figure out max_rtt and sum_rtt
                uint32_t dm = (state->max_rtt - state->base_rtt);
                uint32_t da = (state->sum_rtt / state->cnt_rtt); // was using do_div??
                state->alpha = alpha(state, da, dm);
                state->beta = beta(da, dm);
            }
            rtt_reset(state);
        }

        void TCPIllinois::rtt_reset(TCPIllinoisStateVariables *& state) {
//            state->end_seq = tp->snd_nxt;
            state->cnt_rtt = 0;
            state->sum_rtt = 0;
        }

        /*
        * Compute value of alpha used for additive increase.
        * If small window then use 1.0, equivalent to Reno.
        *
        * For larger windows, adjust based on average delay.
        * A. If average delay is at minimum (we are uncongested),
        * then use large alpha (10.0) to increase faster.
        * B. If average delay is at maximum (getting congested)
        * then use small alpha (0.3)
        *
        * The result is a convex window growth curve.
        */
        uint32_t TCPIllinois::alpha(TCPIllinoisStateVariables *& state, uint32_t da, uint32_t dm) {
            uint32_t d1 = dm / 100;

            if (da <= d1) {
                /* If never got out of low delay zone, then use max */
                if (!state->rtt_above) { return ALPHA_MAX; }
                /* Wait for 5 good RTT's before allowing alpha to go alpha max.
                * This prevents one good RTT from causing sudden window increase.
                */
                if (++state->rtt_low < theta) { return state->alpha; }

                state->rtt_low = 0;
                state->rtt_above = 0;

                return ALPHA_MAX;
            }

            state->rtt_above = 1;

           /*
            * Based on:
            *
            * (dm - d1) amin amax
            * k1 = -------------------
            * amax - amin
            *
            * (dm - d1) amin
            * k2 = ---------------- - d1
            * amax - amin
            *
            * k1
            * alpha = ----------
            * k2 + da
            */
            dm -= d1;
            da -= d1;
            return (dm * ALPHA_MAX) / (dm + (da * (ALPHA_MAX - ALPHA_MIN)) / ALPHA_MIN);
        }

        /*
        * Beta used for multiplicative decrease.
        * For small window sizes returns same value as Reno (0.5)
        *
        * If delay is small (10% of max) then beta = 1/8
        * If delay is up to 80% of max then beta = 1/2
        * In between is a linear function
        */
        uint32_t TCPIllinois::beta(uint32_t da, uint32_t dm) {
            uint32_t d2, d3;
            d2 = dm / 10;

            if (da <= d2) { return BETA_MIN; }

            d3 = (8 * dm) / 10;

            if (da >= d3 || d3 <= d2) { return BETA_MAX; }

            /*
            * Based on:
            *
            * bmin d3 - bmax d2
            * k3 = -------------------
            * d3 - d2
            *
            * bmax - bmin
            * k4 = -------------
            * d3 - d2
            *
            * b = k3 + k4 da
            */
            return (BETA_MIN * d3 - BETA_MAX * d2 + (BETA_MAX - BETA_MIN) * da) / (d3 - d2);
        }
    }
}
