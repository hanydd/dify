from dataclasses import dataclass
from typing import List, Optional, Dict, Any

@dataclass
class ConfigData:
    """ConfigData类"""
    name: Optional[str] = None
    label: Optional[str] = None
    placeholder: Optional[str] = None
    formStyle: Optional[str] = None
    ifNecessary: Optional[str] = None
    ifUnique: Optional[str] = None
    defaultValue: Optional[Any] = None
    rule: Optional[str] = None
    regexText: Optional[str] = None
    radioList: Optional[List[Dict[str, Any]]] = None
    savePoint: Optional[bool] = None
    pointNumber: Optional[int] = None
    range: Optional[Dict[str, Any]] = None
    dateType: Optional[str] = None
    defaultValueType: Optional[str] = None
    numberRules: Optional[List[Dict[str, Any]]] = None
    formula: Optional[Dict[str, Any]] = None
    userType: Optional[str] = None
    valueFrom: Optional[str] = None
    level: Optional[str] = None


@dataclass
class ServicePropertyData:
    """ServicePropertyData类"""
    name: Optional[str] = None
    comment: Optional[str] = None
    placeholder: Optional[str] = None
    defaultValue: Optional[Any] = None
    formStyle: Optional[str] = None
    style: Optional[str] = None
    dataType: Optional[str] = None
    ifNecessary: Optional[str] = None
    ifUnique: Optional[str] = None
    relatedProperty: Optional[str] = None
    config: Optional[ConfigData] = None
    value: Optional[Any] = None

@dataclass
class SystemPropertyData:
    """SystemPropertyData类"""
    uuid: Optional[int] = None
    name: Optional[str] = None
    comment: Optional[str] = None
    formStyle: Optional[str] = None
    style: Optional[str] = None
    dataType: Optional[str] = None
    ifNecessary: Optional[str] = None
    ifUnique: Optional[str] = None
    config: Optional[ConfigData] = None
    value: Optional[Any] = None

@dataclass
class NodeObject:
    """NodeObject类"""
    serviceProperty: Optional[List[ServicePropertyData]] = None
    systemProperty: Optional[List[SystemPropertyData]] = None
    label: Optional[str] = None
    comment: Optional[str] = None
    relateEdge: Optional[str] = None
    subNodes: Optional[List['NodeObject']] = None  # 自引用类型


@dataclass
class IORCConfig:
    """IORCConfig类"""
    inputNodes: Optional[List[NodeObject]] = None  # sipoc的i
    outputNodes: Optional[List[NodeObject]] = None  # sipoc的o
    controlNodes: Optional[List[NodeObject]] = None  # sipoc的c
    resourceNodes: Optional[List[NodeObject]] = None # sipoc中的r

@dataclass
class SipocModelConfig:
    """SipocModelConfig类"""
    modelContext: Optional[IORCConfig] = None  # 给dify的输入变量
    modelGenerate: Optional[IORCConfig] = None  # dify的生成变量
    modelContextKV: Optional[Dict[str, Any]] = None  # 给dify的输入变量转化为kv
    modelGenerateKV: Optional[Dict[str, Any]] = None  # dify的生成变量转化为kv

