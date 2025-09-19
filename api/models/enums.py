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
    # 文档
    GENERATE_DOCUMENT = "generate_document"
    # 表单
    FILL_FORM = "fill_form"
    # 实物
    PHYSICAL = "physical"
    # 数据
    DATA_FORM = "data_form"
    # 数模
    MATH_MODEL = "math_model"
    # 未定义
    UNDEFINED = "undefined"
