import abc


class BaseVaultInitLock(abc.ABC):
    @abc.abstractmethod
    def acquire(self) -> None:
        pass


class BaseProvider(abc.ABC):
    @abc.abstractmethod
    def wait_disk_attached(self, disk_id: str, device: str) -> None:
        pass

    @abc.abstractmethod
    def wait_network_interface(self) -> None:
        pass

    @abc.abstractmethod
    def get_vault_initializer(self) -> BaseVaultInitLock:
        pass

    @abc.abstractmethod
    def save_root_token(self, root_token: str) -> None:
        pass

    @abc.abstractmethod
    def get_root_token(self) -> str:
        pass
