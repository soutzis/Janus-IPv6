from abc import ABCMeta, abstractmethod


class AbstractRepository(metaclass=ABCMeta):

    @abstractmethod
    def truncate_table(self):
        pass

    @abstractmethod
    def disconnect(self):
        pass


class LogRepository(AbstractRepository):

    @abstractmethod
    def get_all_logs(self):
        pass

    @abstractmethod
    def get_logs_by(self, *,
                    date,
                    time,
                    mac_src,
                    mac_dst,
                    ip_src,
                    ip_dst,
                    action,
                    justification,
                    trust_level):
        pass

    @abstractmethod
    def clear_logs(self):
        pass


class RulesetRepository(AbstractRepository):

    @abstractmethod
    def get_ruleset(self, name):
        pass

    def update_ruleset(self, name, ruleset):
        pass


class FlowRepository(AbstractRepository):

    @abstractmethod
    def insert(self, entry):
        pass

    @abstractmethod
    def update(self, current_entry, new_entry):
        pass

    @abstractmethod
    def delete(self, entry):
        pass

    @abstractmethod
    def get_flow_table(self):
        pass

    @abstractmethod
    def get_flow(self, entry):
        pass


class RoutingRepository(AbstractRepository):

    @abstractmethod
    def get_routing_table(self):
        pass

    @abstractmethod
    def prefix_exists(self, prefix):
        pass

    @abstractmethod
    def get_hosts_with_prefix(self, prefix):
        pass

    @abstractmethod
    def insert(self, entry):
        pass

    @abstractmethod
    def update(self, current_entry, new_entry):
        pass

    @abstractmethod
    def delete(self, entry):
        pass
