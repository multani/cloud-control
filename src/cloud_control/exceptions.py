class CloudControlError(Exception):
    pass


class VaultInitConflict(CloudControlError):
    pass
