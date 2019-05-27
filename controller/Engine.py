from enum import Enum
from random import randint
# from typing import List, Sequence

from ryu.lib.packet import ipv6


class AnalysisResult(Enum):
    passed = "PASSED ANALYSIS"
    normalised = "NORMALISABLE AMBIGUITY DETECTED"
    failed = "DID NOT PASS ANALYSIS"
    blocked = "TOO MANY OFFENDING PACKETS"


class Action(Enum):
    forward = "FORWARDED"
    block = "SENDER BLOCKED"
    drop = "DROPPED"
    normalise = "NORMALISED"
    normalise_forward = "NORMALISED & FORWARDED"


class TrustLevel(Enum):
    trusted = "TRUSTED"
    untrusted = "UNTRUSTED"
    blocked = "BLOCKED"


class SyntaxAnalyser:

    # Type alias for list to be returned when packet analysis is complete.
    # AnalysisVector and List[TrustLevel, Action, AnalysisResult, ipv6.ipv6] are treated as interchangeable synonyms.
    # AnalysisVector = Sequence[TrustLevel, Action, AnalysisResult, ipv6.ipv6]

    def __init__(self):
        self.version = 6
        self.traffic_class = 0
        self.incoming_hop_limit_required = 5  # for outgoing change value to +(1-8)
        self.flabel_def_value = 0  # 0xfffff -> 20-bits. This is the max value a flow label can have. Default is 0
        self.jumbogram_starting_length = 65536  # datagrams that have this payload length or higher, are jumbograms
        self.frag_nxt_hdr_value = 44  # Next Header field of a Fragmentation Header should be '44'

        self.norm_eng = Normaliser()
        self.sem_anal = SemanticsAnalyser()

    def analyse(self, pkt: ipv6.ipv6, in_port, wan_port, hosts: list) -> list:
        """
        This function should return a tuple with the results of the analysis/normalisation + the processed packet:
        I.e: (Trustlevel, Action, Result, ipv6.ipv6)  # shows types of tuple members
        Janus is responsible for making the final decision about a packet, based on these results.
        :param pkt: The IPv6 packet to analyse
        :param in_port: The port that the packet arrived from
        :param wan_port: The port that connects Janus to the internet
        :param hosts: The hosts that are in the network protected by Janus
        """
        # ============================================= #
        # Analysis (+ Normalisation of hop limit field) #
        # ============================================= #

        # Will hold either True or False for each field analysed. A field of False, means that it should be passed
        # to the normaliser to attempt to reset the field to the default value

        analysis_results = {
            'version': self._analyse_version(pkt),  # normalise if false
            'traffic_class': self._analyse_traffic_class(pkt),  # normalise if false
            'flow_label': self._analyse_flabel(pkt),  # normalise if false
            'payload_length': self._analyse_payload_length(pkt),  # drop if false
            'fragment_header': self._analyse_fragment_hdr(pkt),  # normalise if false + semantics
            'network_analysis': self._analyse_network(pkt, in_port, wan_port, hosts)  # block if false
        }

        # Initially set to: ["Trusted, Forward, Passed"]
        trust = TrustLevel.trusted
        action = Action.forward
        result = AnalysisResult.passed

        # This normalisation is always performed, so it will NOT yield a result ("NORMALISED")
        result_pkt = self.norm_eng.normalise_hop_limit(pkt, in_port, wan_port, self.incoming_hop_limit_required)

        # ============================================= #
        #                 Normalisation                 #
        # ============================================= #
        if analysis_results['network_analysis'] is False:
            return [TrustLevel.blocked, Action.block, AnalysisResult.failed, result_pkt]

        if analysis_results['version'] is False:
            result_pkt = self.norm_eng.normalize_version(result_pkt, self.version)
            action = Action.normalise

        if analysis_results['traffic_class'] is False:
            result_pkt = self.norm_eng.normalize_tclass(result_pkt, self.traffic_class)
            action = Action.normalise

        if analysis_results['flow_label'] is False:
            result_pkt = self.norm_eng.normalize_flabel(result_pkt, self.flabel_def_value)
            # leave action as is, because flow label is used

        if analysis_results['payload_length'] is False:
            action = Action.drop

        if analysis_results['fragment_header'] is False:
            result_pkt = self.norm_eng.normalise_fragment_header(result_pkt, self.frag_nxt_hdr_value)

        # ============================================= #
        #       Send results for semantic analysis      #
        # ============================================= #

        # Steps to follow if the analysis determined that packet could successfully be normalised
        if action == Action.normalise:
            verdict = self.sem_anal.observe_pkt(result_pkt)
            trust = verdict[0]
            action = verdict[1]

            # If semantic analyzer decided to forward
            if action == Action.forward:
                action = Action.normalise_forward
                result = AnalysisResult.normalised

            # If semantic analyzer decided to block
            elif action == Action.block:
                result = AnalysisResult.blocked

        # Steps to follow if analysis determined that packet should be dropped
        elif action == Action.drop:
            verdict = self.sem_anal.observe_pkt(result_pkt)
            trust = verdict[0]

            if verdict[1] == Action.block:
                action = Action.block
                result = AnalysisResult.blocked
            else:
                result = AnalysisResult.failed

        # Steps for fragment header
        if (action is not Action.block) and (action is not Action.drop):
            # If there is a fragment header, send for semantic dissection, else skip this step
            if analysis_results['fragment_header'] is not None:
                # Get verdict from semantic analyser
                verdict = self.sem_anal.observe_fragment(result_pkt)
                if trust is TrustLevel.trusted:
                    if verdict[0] is not TrustLevel.trusted:

                        trust = verdict[0]
                        action = verdict[1]
                        if action is Action.drop:
                            result = AnalysisResult.failed

                        elif action is Action.block:
                            result = AnalysisResult.blocked

                        elif action is Action.forward:
                            result = AnalysisResult.normalised

        return [trust, action, result, result_pkt]

    # #######  Fine-grain analysis methods below  ####### #
    def _analyse_version(self, pkt: ipv6.ipv6) -> bool:
        version = self.version
        if pkt.version is not version:
            return False
        else:
            return True

    def _analyse_traffic_class(self, pkt: ipv6.ipv6) -> bool:
        traffic_class = self.traffic_class
        if pkt.traffic_class is not traffic_class:
            return False
        else:
            return True

    def _analyse_flabel(self, pkt: ipv6.ipv6) -> bool:
        if pkt.flow_label != self.flabel_def_value:
            return False
        else:
            return True

    def _analyse_payload_length(self, pkt: ipv6.ipv6) -> bool:
        max_payload_length = self.jumbogram_starting_length - 1  # set the maximum payload length of a non-jumbo
        if pkt.payload_length > max_payload_length:
            return False
        else:
            return True

    def _analyse_fragment_hdr(self, pkt: ipv6.ipv6) -> bool or None:
        extension_headers = pkt.ext_hdrs
        fragment_hdr = None
        next_header = None

        # Check if the packet is a fragment and if it has a fragment extension header
        for ext_hdr in extension_headers:
            if isinstance(ext_hdr, ipv6.fragment):
                fragment_hdr = ext_hdr  # assign to var, so it can be examined
                next_header = self.frag_nxt_hdr_value  # if frag_hdr was detected, initialise expected value

        # If this packet has no fragment header, return true
        if fragment_hdr is None:
            return fragment_hdr

        # Start analysis of fragment_hdr
        if fragment_hdr.nxt != next_header:
            return False
        # Fragment can't be the first fragment and be the last fragment too!
        if (fragment_hdr.offset == 0) and fragment_hdr.more == 0:
            return False
        # Fragment can't have a value which can't be divided by 8
        if ((fragment_hdr.offset % 8) != 0) and fragment_hdr.more == 1:
            return False
        # ####### Should be able to check for Fragment header reserved values, but Ryu doesn't support them ####### #
        # If all checks are passed, return True
        return True

    @staticmethod
    def _analyse_network(pkt: ipv6.ipv6, in_port, wan_port, hosts):

        # If packet came from outside the protected network
        if in_port == wan_port:
            if pkt.dst not in hosts:
                return False
            else:
                return True
        # If packet came from inside the protected network
        else:
            if pkt.src not in hosts:
                return False
            else:
                return True


class Normaliser:

    @staticmethod
    def normalise_fragment_header(pkt: ipv6.ipv6, default_nxt_hdr) -> ipv6.ipv6:
        for i in range(len(pkt.ext_hdrs)):
            if isinstance(pkt.ext_hdrs[i], ipv6.fragment):
                pkt.ext_hdrs[i].nxt = default_nxt_hdr
                pkt.ext_hdrs[i].serialize()

        return pkt

    @staticmethod
    def normalize_flabel(pkt: ipv6.ipv6, def_value) -> ipv6.ipv6:
        pkt.flow_label = def_value

        return pkt

    @staticmethod
    def normalize_version(pkt: ipv6.ipv6, norm_version) -> ipv6.ipv6:
        pkt.version = norm_version

        return pkt

    @staticmethod
    def normalize_tclass(pkt: ipv6.ipv6, norm_tclass) -> ipv6.ipv6:
        pkt.traffic_class = norm_tclass

        return pkt

    @staticmethod
    def normalise_hop_limit(pkt: ipv6.ipv6, in_port, wan_port, hop_limit) -> ipv6.ipv6:

        predefined_hop_limit = hop_limit

        # If packet is incoming to protected network, then add an arbitrary value between -2 and +2.
        # E.g if incoming packet to protected network has a hop_limit value of 243, then change that to
        # the value needed to reach a packet in the network (preset as 5). Then add an arbitrary value (i.e -1) to it
        # : 250 => 5 => 5 + (-1) = 4. The arbitrary value is added to make it harder for an adversary to notice the
        # normalisation that takes place
        if in_port == wan_port:
            pkt.hop_limit = predefined_hop_limit + randint(-2, 2)

        # Else, packet is outgoing (from protected network to WAN). In this case, in an attempt to NOT break the
        # communication, a small value is added (-1 to +5), in order to introduce noise to the possibly modified
        # value and disrupt the covert channel (NOT 100% ELIMINATION)
        else:
            pkt.hop_limit += randint(-1, 5)

        return pkt


class SemanticsAnalyser:
    # observer style could be key: src address, value {key: field, value: analysis result}
    # more than 25 normalisations for covertness should result in blocking the sender for 8 hours (28800 seconds)
    # ( for fragments that were observed as anomalous, block after 10 anomalies )
    ambiguity_observer = {}
    fragments_observer = {}
    # VerdictVector = List[TrustLevel, Action]

    @staticmethod
    def observe_pkt(pkt: ipv6.ipv6) -> list:
        pkt_id_tuple = (pkt.src, pkt.dst)

        if pkt_id_tuple not in SemanticsAnalyser.ambiguity_observer.keys():
            SemanticsAnalyser.ambiguity_observer[pkt_id_tuple] = 0

        elif SemanticsAnalyser.ambiguity_observer[pkt_id_tuple] >= 10:
            SemanticsAnalyser.ambiguity_observer[pkt_id_tuple] = 0
            return [TrustLevel.blocked, Action.block]

        SemanticsAnalyser.ambiguity_observer[pkt_id_tuple] += 1

        return [TrustLevel.untrusted, Action.forward]

    @staticmethod
    def observe_fragment(pkt: ipv6.ipv6) -> list:

        pkt_id_tuple = (pkt.src, pkt.dst)
        frag_hdr = None
        trust = TrustLevel.trusted
        action = Action.forward

        for i in range(len(pkt.ext_hdrs)):
            if isinstance(pkt.ext_hdrs[i], ipv6.fragment):
                frag_hdr = i

        SemanticsAnalyser.fragments_observer.setdefault(pkt_id_tuple, {})

        if pkt_id_tuple not in SemanticsAnalyser.fragments_observer.keys():
            SemanticsAnalyser.fragments_observer[pkt_id_tuple]['count'] = 0
            SemanticsAnalyser.fragments_observer[pkt_id_tuple]['offset'] = []

        elif (pkt_id_tuple in SemanticsAnalyser.fragments_observer.keys()) and pkt.ext_hdrs[frag_hdr].offset == 0:
            SemanticsAnalyser.fragments_observer[pkt_id_tuple]['count'] = 0
            SemanticsAnalyser.fragments_observer[pkt_id_tuple]['offset'] = []

        elif SemanticsAnalyser.fragments_observer[pkt_id_tuple] >= 10:
            return [TrustLevel.blocked, Action.block]

        # Fragment can't be the first fragment and be the last fragment too!
        if (pkt.ext_hdrs[frag_hdr].offset == 0) and pkt.ext_hdrs[frag_hdr].more == 0:
            SemanticsAnalyser.fragments_observer[pkt_id_tuple]['count'] += 1
            trust = TrustLevel.untrusted
            action = Action.drop

        # Fragment can't have a value which can't be divided by 8
        elif ((pkt.ext_hdrs[frag_hdr].offset % 8) != 0) and pkt.ext_hdrs[frag_hdr].more == 1:
            SemanticsAnalyser.fragments_observer[pkt_id_tuple]['count'] += 1
            trust = TrustLevel.untrusted
            action = Action.drop

        elif pkt.ext_hdrs[frag_hdr].offset in SemanticsAnalyser.fragments_observer[pkt_id_tuple]['offset']:
            trust = TrustLevel.untrusted
            action = Action.forward

        return [trust, action]
