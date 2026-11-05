"""Domain-level exceptions translated into HTTP responses by routers."""


class ResourceNotFoundError(Exception):
    pass


class ResourceConflictError(Exception):
    pass


class InvalidStateTransitionError(Exception):
    pass


class BusinessRuleError(Exception):
    pass


class ResourceIncompatibleError(BusinessRuleError):
    pass


class SchedulingConflictError(BusinessRuleError):
    pass


class SecurityPolicyViolationError(BusinessRuleError):
    pass

