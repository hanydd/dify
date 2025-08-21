from enum import StrEnum


class CreatorUserRole(StrEnum):
    ACCOUNT = "account"
    END_USER = "end_user"


class UserFrom(StrEnum):
    ACCOUNT = "account"
    END_USER = "end-user"


class WorkflowRunTriggeredFrom(StrEnum):
    DEBUGGING = "debugging"
    APP_RUN = "app-run"


class DraftVariableType(StrEnum):
    # node means that the correspond variable
    NODE = "node"
    SYS = "sys"
    CONVERSATION = "conversation"


class MessageStatus(StrEnum):
    """
    Message Status Enum
    """

    NORMAL = "normal"
    ERROR = "error"


class SceneType(StrEnum):
    """
    Scene Type Enum
    """
    GENERATE_DOCUMENT = "生成文档"
    FILL_FORM = "填表单"
    UNDEFINED = "未定义"
