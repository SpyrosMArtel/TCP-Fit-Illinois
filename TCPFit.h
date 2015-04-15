#ifndef __INET_TCPFIT_H
#define __INET_TCPFIT_H

#include "inet/common/INETDefs.h"

#include "inet/transportlayer/tcp/flavours/TCPBaseAlg.h"
#include "inet/transportlayer/tcp/flavours/TCPSegmentTransmitInfoList.h"

namespace inet {

    namespace tcp {

        class INET_API TCPFitStateVariables : public TCPBaseAlgStateVariables {

        public:
            TCPFitStateVariables();
            ~TCPFitStateVariables();

            virtual std::string info() const override;
            virtual std::string detailedInfo() const override;

            uint32 ssthresh;        /* < slow start threshold */
            simtime_t w_RTTmin;     /* min RTT */
            simtime_t epoch_start;  /* dunno */
            simtime_t update_epoch;  /* dunno */
            double alpha;           /* Additive increase */
            double beta;            /* Muliplicative decrease */
            double n;               /* tcp-fit n parameter */
            double cwnd_cnt;        /* Congestion window counter. */
            simtime_t RTT_cnt;         /* rtt counter */
            uint32 ACK_cnt;         /* ACK counter */
            simtime_t avgRTT;          /* average Round Trip time; */

            simtime_t w_lastAckTime;    // last received ack time

            TCPSegmentTransmitInfoList regions;

        private:
        };

        class TCPFit : public TCPBaseAlg {
        protected:
            TCPFitStateVariables *& state;    // alias to TCPFit algorithm's 'state'

          /** Create and return a TCPFitStateVariables object. */
          virtual TCPStateVariables *createStateVariables() override {
              return new TCPFitStateVariables();
          }

          /** Utility function to recalculate ssthresh */
          virtual void recalculateSlowStartThreshold();
          /** Redefine what should happen on retransmission */
          virtual void processRexmitTimer(TCPEventCode& event) override;

        public:
          /** Ctor */
          TCPFit();

          /** Redefine what should happen when data got acked, to add congestion window management */
          virtual void receivedDataAck(uint32 firstSeqAcked) override;

          /** Redefine what should happen when dupAck was received, to add congestion window management */
          virtual void receivedDuplicateAck() override;

          /** Called after we send data */
          virtual void dataSent(uint32 fromseq) override;

          virtual void segmentRetransmitted(uint32 fromseq, uint32 toseq) override;

          virtual void tcpFitUpdateN();

        private:
          simtime_t currentTime; // current time in simulation

          virtual void tcpFitReset();
        };

    } // namespace tcp
} // namespace inet
#endif
