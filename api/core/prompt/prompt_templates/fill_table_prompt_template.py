FILL_TABLE_PROMPT_TEMPLATE = """
你是一个知识渊博的表格填写专家， 你能根据给定的待填表格和代填信息数据来源， 以及用户特定的填写要求， 将相关的数据整理成恰当的形式，并填入正确的表格位置。
注意，你是以json格式的格式来实现表格填写， 对待填表格中未提及的字段无需进行填写。

以下是示例：
待填表格：
[output:##node##vacation-requirement:##prop##name, output:##node##vacation-requirement:##prop##sex, output:##node##vacation-requirement:##edge##vacation.##prop##vacation_type,
output:##node##vacation-requirement:##edge##vacation.##prop##reason, output:##node##vacation-requirement:##edge##vacation.##prop##time, output:##node##vacation-requirement:##prop##sign]
待填字段详情：
{
		"inputNodes": [
			{
				"label": "productQuery",
				"comment": "产品查询条件",
				"relateEdge": "",
				"property": [
					{ "name": "productName", "type": "单行文本", "value": "" },
					{ "name": "priceRange", "type": "数值", "unit": "元", "value": "" },
					{ "name": "categories", "type": "多选", "options": ["电子产品", "服装", "食品"], "value": "" }
				],
				"subNodes": []
			}
		],
		"outputNodes": [
			{
				"label": "analysisResult",
				"comment": "数据分析结果",
				"relateEdge": "",
				"property": [
					{ "name": "salesTrend", "type": "图片", "value": "" },
					{ "name": "userPortrait", "type": "富文本", "value": "" },
					{ "name": "riskAssessment", "type": "单选", "options": ["低风险", "中风险", "高风险"], "value": "" }
				],
				"subNodes": [
					{
						"label": "detailData",
						"comment": "详细数据明细",
						"relateEdge": "analysisResult",
						"Property": [
							{ "name": "region", "type": "单行文本", "value": "" },
							{ "name": "salesVolume", "type": "数值", "unit": "件", "value": "" },
							{ "name": "growthRate", "type": "数值", "unit": "%", "value": "" }
						],
						"subNodes": []
					}
				]
			}
		],
		"controlNodes": [
			{
				"label": "notificationSetting",
				"comment": "通知配置",
				"relateEdge": "",
				"property": [
					{ "name": "notifyType", "type": "多选", "options": ["短信", "邮件", "站内信"], "value": "" },
					{ "name": "triggerCondition", "type": "公式", "expression": "amount > 1000", "value": "" },
					{ "name": "template", "type": "附件", "value": "" }
				],
				"subNodes": []
			}
		]
	}
信息数据来源：
1、
{
    <input>:##node##description.##prop##creator: "张三",
    <input>:##node##description.##prop##text: "领导，昨天我不小心扭到了脚，特向您申请一天病假。"
}
2、
{
    <control>:##node##vacation-regulation.##prop##text: "员工请假管理制度规范\n\n一、目的\n\n为规范员工请假行为，保障公司正常运作和工作秩序，明确请假流程和审批权限，特制定本制度。\n\n二、适用范围\n\n本制度适用于公司全体正式员工及试用期员工。\n\n三、请假类型及说明\n\n事假\n\n因个人事务需离岗，必须提前申请。\n\n事假期间不计薪。\n\n病假\n\n因疾病或身体原因无法工作，需提供正规医疗机构病假证明。\n\n病假薪资待遇按公司及相关法律规定执行。\n\n年假\n\n连续工作满12个月的员工享有带薪年休假，天数按国家法律及公司规定执行。\n\n年假需提前申请并经部门安排，不得集中在业务高峰期使用（特殊情况需总经理批准）。\n\n产假\n\n按国家法律规定执行，需提供相应的医学证明或出生证明。\n\n四、请假申请流程\n\n提前申请\n\n事假、年假：应至少提前1个工作日提出申请。\n\n病假：因突发疾病不能提前申请的，应在请假当天尽快通知主管，并于返回工作后补交病假证明。\n\n产假、婚假等长期假期：应至少提前15天提出申请。\n\n审批权限\n\n1天（含）以内：由直接主管批准。\n\n2-3天：由部门负责人批准。\n\n4天及以上或跨部门影响工作安排的：由人力资源部审核，总经理批准。\n\n请假方式\n\n通过公司OA系统、书面请假单或电子邮件提交。\n\n紧急情况下可先电话或即时通讯工具通知主管，并在24小时内补交请假申请。\n\n五、注意事项\n\n无故旷工一天按旷工处理，旷工三天（含）以上，公司有权解除劳动合同。\n\n请假期间如需续假，应提前至少半天通知主管并提交申请。\n\n假期结束应按时返回工作岗位，提前返岗需报备主管。\n\n虚假请假、伪造证明，一经查实，按严重违纪处理。\n\n六、附则\n\n本制度未尽事宜，按国家法律法规及公司相关管理制度执行。\n\n本制度由人力资源部负责解释，并自发布之日起执行。"
}
用户填写要求：帮我填写一下病假单。
表格填写结果：
{
    output:##node##vacation-requirement:##prop##name: "张三",
    output:##node##vacation-requirement:##prop##sex: "",
    output:##node##vacation-requirement:##edge##vacation.##prop##vacation_type: "病假",
    output:##node##vacation-requirement:##edge##vacation.##prop##reason: "不小心扭到脚了",
    output:##node##vacation-requirement:##edge##vacation.##prop##time: "一天",
    output:##node##vacation-requirement:##prop##sign: ""
}

以下是真实场景：
待填表格：
{{#output_results#}}
待填字段详情：
{{#output_related_information#}}  //
信息数据来源:
{{#input_key_values#}}

表格填写结果：
"""
