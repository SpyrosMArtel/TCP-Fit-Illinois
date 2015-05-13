#ifndef TCPILLINOIS_H_
#define TCPILLINOIS_H_

#include "inet/common/INETDefs.h"

#include "inet/transportlayer/tcp/flavours/TCPTahoeRenoFamily.h"
#include "inet/transportlayer/tcp/flavours/TCPSegmentTransmitInfoList.h"

namespace inet {

    namespace tcp {

        class INET_API TCPIllinoisStateVariables : public TCPBaseAlgStateVariables {

        public:
            TCPIllinoisStateVariables();
            ~TCPIllinoisStateVariables();

            virtual std::string info() const override;
            virtual std::string detailedInfo() const override;

            simtime_t   base_rtt;   /* min of all rtt in usec */
            simtime_t	max_rtt;   /* max of all rtt in usec */

            uint64_t    sum_rtt;   /* sum of rtt's measured within last rtt */
            uint64_t    snd_cwnd_cnt; /* # of packets since last cwnd increment */
            uint64_t    ssthresh;        /* < slow start threshold */
            uint32_t    snd_cwnd_clamp; /* congestion window top limit */
            uint32_t    end_seq;   /* right edge of current RTT */
            uint32_t    alpha;     /* Additive increase */
            uint32_t    beta;      /* Muliplicative decrease */
            uint16_t    cnt_rtt;   /* # of rtts measured within last rtt */
            uint8_t     rtt_above; /* average rtt has gone above threshold */
            uint8_t     rtt_low;   /* # of rtts measurements below threshold */

            simtime_t w_lastAckTime;    /* last received ack time */

            TCPSegmentTransmitInfoList regions;

        private:
        };

        class TCPIllinois : public TCPBaseAlg {
        protected:
            TCPIllinoisStateVariables *& state;    // alias to TCPIllinois algorithm's 'state'

          /** Create and return a TCPFitStateVariables object. */
          virtual TCPStateVariables *createStateVariables() override {
              return new TCPIllinoisStateVariables();
          }

          /** Utility function to recalculate ssthresh */
          virtual void recalculateSlowStartThreshold();
          /** Redefine what should happen on retransmission */
          virtual void processRexmitTimer(TCPEventCode& event) override;

        public:
          /** Ctor */
          TCPIllinois();

          /** Redefine what should happen when data got acked, to add congestion window management */
          virtual void receivedDataAck(uint32 firstSeqAcked) override;

          /** Redefine what should happen when dupAck was received, to add congestion window management */
          virtual void receivedDuplicateAck() override;

          /** Called after we send data */
          virtual void dataSent(uint32 fromseq) override;

          virtual void segmentRetransmitted(uint32 fromseq, uint32 toseq) override;

          virtual uint32_t alpha(TCPIllinoisStateVariables *& state, uint32_t da, uint32_t dm);

          virtual uint32_t beta(uint32_t da, uint32_t dm);

          virtual void update_params(TCPIllinoisStateVariables *& state);

          virtual void rtt_reset(TCPIllinoisStateVariables *& state);

        private:
          simtime_t currentTime; // current time in simulation

        };
    }

}
#endif /* TCPILLINOIS_H_ */
