"""Which rules check which best practices of the AI lenses (data/ai_lenses.json).

This is the lens twin of wa_map.RULE_BEST_PRACTICES. It is a separate table so the 57-question
core answers do not move: a rule listed here answers one lens question and never a core one.

LENS_NOT_CHECKED lists every lens best practice that has no rule yet. tests/test_ai_lenses.py
fails when a best practice is in neither this table nor LENS_NOT_CHECKED, or in both. A rule
that covers a practice adds it to LENS_RULE_BEST_PRACTICES and drops it from
LENS_NOT_CHECKED in the same change.
"""
from __future__ import annotations

# rule id -> the lens best practices it checks. One rule, one lens question.
LENS_RULE_BEST_PRACTICES: dict[str, tuple[str, ...]] = {
    # Bedrock and SageMaker template checks (rules/cf_template.py, _ai_findings).
    "CF-BEDROCK-001": ("GENSEC02-BP01",),
    "CF-BEDROCK-003": ("GENREL03-BP02",),
    "CF-BEDROCK-004": ("GENSEC03-BP01",),
    "CF-SAGE-006": ("MLPERF06-BP04",),
    "CF-BEDROCK-005": ("AGENTSEC04-BP01",),
    "CF-BEDROCK-006": ("GENSEC04-BP01",),
    "CF-BEDROCK-007": ("AGENTOPS02-BP03",),
    "CF-BEDROCK-008": ("GENREL04-BP01",),
    "CF-BEDROCK-009": ("GENCOST03-BP02",),
    # AgentCore template checks (the same function).
    "CF-AGENTCORE-001": ("GENSEC01-BP02",),
    "CF-AGENTCORE-002": ("AGENTSEC02-BP01",),
    "CF-AGENTCORE-003": ("AGENTSEC01-BP01",),
    # Guardrail topic, PII and grounding checks (the same function): the Responsible AI lens.
    "CF-BEDROCK-010": ("RAIBR04-BP01",),
    "CF-BEDROCK-011": ("RAISP03-BP01",),
    "CF-BEDROCK-012": ("RAISP03-BP04",),
    # Guardrail prompt attack and response filters (the same function): AGENTSEC 8.
    "CF-BEDROCK-013": ("AGENTSEC08-BP01",),
    "CF-BEDROCK-014": ("AGENTSEC08-BP02",),
    # Agent role trust and boundary (the same function): AGENTSEC 3.
    "CF-BEDROCK-015": ("AGENTSEC03-BP02",),
    "CF-BEDROCK-016": ("AGENTSEC03-BP03",),
    # Agent role scope (the same function): GENSEC 5.
    "CF-BEDROCK-017": ("GENSEC05-BP01",),
    # Guardrail harmful-content filters on each side (the same function): RAISP 3.
    "CF-BEDROCK-018": ("RAISP03-BP02",),
    "CF-BEDROCK-019": ("RAISP03-BP03",),
    # Model and data store access scope (the same function): GENSEC 1, MLSEC 3.
    "CF-BEDROCK-020": ("GENSEC01-BP01",),
    "CF-BEDROCK-021": ("GENSEC01-BP03",),
    "CF-SAGE-016": ("MLSEC03-BP01",),
    # SageMaker notebook, domain, endpoint, feature group and model checks (the same function).
    "CF-SAGE-007": ("MLCOST04-BP08",),
    "CF-SAGE-008": ("MLSEC03-BP02",),
    "CF-SAGE-009": ("MLSEC02-BP01",),
    "CF-SAGE-010": ("MLOPS06-BP02",),
    "CF-SAGE-011": ("MLREL05-BP01",),
    "CF-SAGE-012": ("MLSEC02-BP01",),
    "CF-SAGE-013": ("MLREL05-BP02",),
    "CF-SAGE-014": ("MLSEC06-BP01",),
    "CF-SAGE-015": ("RAIMON01-BP03",),
    # Repo-note checks (rules/repo_practices.py, the AI lens rules).
    "REPO-194": ("RAIUC05-BP01",),
    "REPO-195": ("GENPERF01-BP01",),
    "REPO-196": ("RAIUC04-BP02",),
    "REPO-197": ("AGENTOPS01-BP01",),
    "REPO-198": ("GENSEC04-BP01",),
    # Code and CI checks on an AI workload (rules/repo_practices.py, the AI code rules).
    "REPO-199": ("GENSEC02-BP01",),
    "REPO-200": ("GENCOST03-BP02",),
    "REPO-201": ("GENOPS01-BP01",),
    # Responsible AI governance on an AI workload (rules/repo_practices.py, the AI note rules).
    "REPO-202": ("RAIGT01-BP02",),
    "REPO-203": ("RAIRC03-BP02",),
    "REPO-204": ("RAIMON01-BP05",),
    # AGENTSEC 9 security testing of an agent (rules/repo_practices.py, the agent security rules).
    "REPO-205": ("AGENTSEC09-BP01", "AGENTSEC09-BP02", "AGENTSEC09-BP03"),
    "REPO-206": ("AGENTSEC09-BP04",),
    "REPO-207": ("AGENTSEC09-BP05",),
    # AGENTSEC 7 human oversight and rogue agents (rules/repo_practices.py, the agent oversight rules).
    "REPO-208": ("AGENTSEC07-BP01", "AGENTSEC07-BP02", "AGENTSEC07-BP03"),
    "REPO-209": ("AGENTSEC07-BP04",),
    "REPO-210": ("AGENTSEC07-BP05",),
    # AGENTSEC 6 multi-agent orchestration (rules/repo_practices.py, the multi-agent rules).
    "REPO-211": ("AGENTSEC06-BP01", "AGENTSEC06-BP02", "AGENTSEC06-BP03"),
    "REPO-212": ("AGENTSEC06-BP04",),
    # AGENTSEC 5 observability and non-repudiation (rules/repo_practices.py, the agent record rules).
    "REPO-213": ("AGENTSEC05-BP01",),
    "REPO-214": ("AGENTSEC05-BP02",),
    # AGENTSEC 3 agent identities and permissions (rules/repo_practices.py, the agent identity rules).
    "REPO-215": ("AGENTSEC03-BP01",),
    "REPO-216": ("AGENTSEC03-BP04",),
    # GENSEC 6 data poisoning (rules/repo_practices.py, the training data rule).
    "REPO-217": ("GENSEC06-BP01",),
    # Machine Learning lens security (rules/repo_practices.py, the ML security rules).
    "REPO-218": ("MLSEC01-BP01",),
    "REPO-219": ("MLSEC04-BP01",),
    "REPO-220": ("MLSEC04-BP02",),
    "REPO-221": ("MLSEC04-BP03",),
    "REPO-222": ("MLSEC05-BP01",),
    "REPO-223": ("MLSEC06-BP02",),
    # The remaining AGENTSEC and AGENTOPS practices (rules/repo_practices.py, the agent practice rules).
    "REPO-224": ("AGENTSEC04-BP02",),
    "REPO-225": ("AGENTSEC02-BP02",),
    "REPO-226": ("AGENTSEC02-BP03",),
    "REPO-227": ("AGENTSEC01-BP02",),
    "REPO-228": ("AGENTSEC01-BP03",),
    "REPO-229": ("AGENTOPS02-BP01",),
    "REPO-230": ("AGENTOPS02-BP02",),
    "REPO-231": ("AGENTOPS02-BP04",),
    "REPO-232": ("AGENTOPS01-BP02",),
    "REPO-233": ("AGENTOPS01-BP03",),
    # Responsible AI lens: workflow, harms, metrics, monitoring and guidance (rules/repo_practices.py, the RAI rules).
    "REPO-234": ("RAIUC04-BP01",),
    "REPO-235": ("RAIUC04-BP03",),
    "REPO-236": ("RAIBR04-BP02", "RAIBR04-BP03"),
    "REPO-237": ("RAIRC03-BP01",),
    "REPO-238": ("RAIRC03-BP03",),
    "REPO-239": ("RAIRC03-BP04",),
    "REPO-240": ("RAIRC03-BP05",),
    "REPO-241": ("RAIRC03-BP07",),
    "REPO-242": ("RAIRC03-BP08",),
    "REPO-243": ("RAIRC03-BP09",),
    "REPO-244": ("RAIRC03-BP10",),
    "REPO-245": ("RAIMON01-BP01",),
    "REPO-246": ("RAIMON01-BP02",),
    "REPO-247": ("RAIMON01-BP04",),
    "REPO-248": ("RAIGT01-BP01", "RAIGT01-BP03"),
    "REPO-249": ("RAIGT01-BP04", "RAIGT01-BP06"),
    # Generative AI and Machine Learning lens Medium practices (rules/repo_practices.py).
    "REPO-250": ("GENSEC04-BP02",),
    "REPO-251": ("GENSEC01-BP04",),
    "REPO-252": ("GENREL04-BP02",),
    "REPO-253": ("GENREL03-BP01",),
    "REPO-254": ("GENPERF01-BP02",),
    "REPO-255": ("GENOPS01-BP02",),
    "REPO-256": ("GENCOST03-BP01",),
    "REPO-257": ("GENCOST03-BP03",),
    "REPO-258": ("GENCOST03-BP04",),
    "REPO-259": ("MLSEC03-BP03",),
    "REPO-260": ("MLSEC03-BP04",),
    "REPO-261": ("MLSEC03-BP05",),
    "REPO-262": ("MLPERF06-BP01",),
    "REPO-263": ("MLPERF06-BP02",),
    "REPO-264": ("MLPERF06-BP03",),
    "REPO-265": ("MLPERF06-BP05",),
    "REPO-266": ("MLPERF06-BP06",),
    "REPO-267": ("MLOPS06-BP01",),
    "REPO-268": ("MLCOST04-BP01", "MLCOST04-BP04", "MLCOST04-BP09", "MLCOST04-BP13", "MLCOST04-BP14"),
    "REPO-269": ("MLCOST04-BP02",),
    "REPO-270": ("MLCOST04-BP03",),
    "REPO-271": ("MLCOST04-BP05",),
    "REPO-272": ("MLCOST04-BP06",),
    "REPO-273": ("MLCOST04-BP07",),
    "REPO-274": ("MLCOST04-BP10",),
    "REPO-275": ("MLCOST04-BP11",),
    "REPO-276": ("MLCOST04-BP12",),
    # MLOPS 1: How does your organizational structure and culture support your busine
    "REPO-277": ("MLOPS01-BP01", "MLOPS01-BP02", "MLOPS01-BP03"),
    # MLOPS 2: How do you establish operational processes that validate and maintain 
    "REPO-278": ("MLOPS02-BP01", "MLOPS02-BP02", "MLOPS02-BP03", "MLOPS02-BP04", "MLOPS02-BP05", "MLOPS02-BP06"),
    # MLOPS 3: How do you plan for continuous development and improvement?
    "REPO-279": ("MLOPS03-BP01", "MLOPS03-BP02"),
    # MLOPS 4: How do you implement operational practices that ensure reproducible an
    "REPO-280": ("MLOPS04-BP01", "MLOPS04-BP02"),
    # MLOPS 5: How do you manage scalable development and deployment?
    "REPO-281": ("MLOPS05-BP01",),
    # MLREL 1: How do you ensure your ML problem formulation accounts for reliability
    "REPO-282": ("MLREL01-BP01", "MLREL01-BP02"),
    # MLREL 2: How do you ensure reliable and resilient data processing pipelines for
    "REPO-283": ("MLREL02-BP01", "MLREL02-BP02", "MLREL02-BP03"),
    # MLREL 3: How do you verify your model development practices result in reliable 
    "REPO-284": ("MLREL03-BP01", "MLREL03-BP02", "MLREL03-BP03", "MLREL03-BP04"),
    # MLREL 4: How do you prepare your ML workload to manage and withstand failures?
    "REPO-285": ("MLREL04-BP01", "MLREL04-BP02"),
    # MLPERF 1: How do you define and align performance requirements with business obj
    "REPO-286": ("MLPERF01-BP01",),
    # MLPERF 2: How do you incorporate performance requirements and constraints into y
    "REPO-287": ("MLPERF02-BP01", "MLPERF02-BP02"),
    # MLPERF 3: How do you evaluate ML performance efficiency and plan for improvement
    "REPO-288": ("MLPERF03-BP01",),
    # MLPERF 4: How do you evolve your architecture and infrastructure?
    "REPO-289": ("MLPERF04-BP01", "MLPERF04-BP02", "MLPERF04-BP03", "MLPERF04-BP04", "MLPERF04-BP05", "MLPERF04-BP06"),
    # MLPERF 5: How do you optimize deployment architectures and processes to achieve 
    "REPO-290": ("MLPERF05-BP01", "MLPERF05-BP02"),
    # MLCOST 1: How do you align expenditure to your business objectives and create us
    "REPO-291": ("MLCOST01-BP01", "MLCOST01-BP02"),
    # MLCOST 2: How do you verify cost considerations are factored into your ML proble
    "REPO-292": ("MLCOST02-BP01", "MLCOST02-BP02"),
    # MLCOST 3: How do you optimize cost during model training?
    "REPO-293": ("MLCOST03-BP01", "MLCOST03-BP02", "MLCOST03-BP03", "MLCOST03-BP04"),
    # MLCOST 5: How do you manage demand and supply resources?
    "REPO-294": ("MLCOST05-BP01", "MLCOST05-BP02", "MLCOST05-BP03"),
    # MLCOST 6: How do you implement cost-effective monitoring strategies while mainta
    "REPO-295": ("MLCOST06-BP01", "MLCOST06-BP02", "MLCOST06-BP03", "MLCOST06-BP04"),
    # MLSUS 1: How do you align sustainability goals with business objectives and cre
    "REPO-296": ("MLSUS01-BP01",),
    # MLSUS 2: How do you incorporate sustainability considerations into your ML prob
    "REPO-297": ("MLSUS02-BP01", "MLSUS02-BP02"),
    # MLSUS 3: How do you implement sustainable data processing practices that minimi
    "REPO-298": ("MLSUS03-BP01", "MLSUS03-BP02", "MLSUS03-BP03"),
    # MLSUS 4: How do you ensure sustainable resource selection and usage?
    "REPO-299": ("MLSUS04-BP01", "MLSUS04-BP02", "MLSUS04-BP03", "MLSUS04-BP04"),
    # MLSUS 5: How do you implement deployment practices that minimize environmental 
    "REPO-300": ("MLSUS05-BP01", "MLSUS05-BP02", "MLSUS05-BP03", "MLSUS05-BP04"),
    # MLSUS 6: How do you implement monitoring practices that minimize environmental 
    "REPO-301": ("MLSUS06-BP01", "MLSUS06-BP02"),
    # GENOPS 2: How do you monitor and manage the operational health of your applicati
    "REPO-302": ("GENOPS02-BP01", "GENOPS02-BP02", "GENOPS02-BP03"),
    # GENOPS 3: How do you maintain traceability for your models, prompts, and assets?
    "REPO-303": ("GENOPS03-BP01", "GENOPS03-BP02"),
    # GENOPS 4: How do you automate the lifecycle management of your generative AI wor
    "REPO-304": ("GENOPS04-BP01", "GENOPS04-BP02"),
    # GENOPS 5: How do you determine when to execute Gen AI model customization?
    "REPO-305": ("GENOPS05-BP01",),
    # GENREL 1: How do you determine throughput quotas (or needs) for foundation model
    "REPO-306": ("GENREL01-BP01",),
    # GENREL 2: How do you maintain reliable communication among different components 
    "REPO-307": ("GENREL02-BP01",),
    # GENREL 5: How do you distribute inference workloads over multiple regions of ava
    "REPO-308": ("GENREL05-BP01", "GENREL05-BP02", "GENREL05-BP03"),
    # GENREL 6: How do you design high-performance distributed computation tasks to ma
    "REPO-309": ("GENREL06-BP01",),
    # GENPERF 2: How do you verify your generative AI workload maintains acceptable per
    "REPO-310": ("GENPERF02-BP01", "GENPERF02-BP02", "GENPERF02-BP03"),
    # GENPERF 3: How do you optimize computational resources required for high-performa
    "REPO-311": ("GENPERF03-BP01",),
    # GENPERF 4: How do you improve the performance of data retrieval systems?
    "REPO-312": ("GENPERF04-BP01", "GENPERF04-BP02"),
    # GENCOST 1: How do you select the appropriate model to optimize costs?
    "REPO-313": ("GENCOST01-BP01",),
    # GENCOST 2: How do you select a cost-effective pricing model (for example, provisi
    "REPO-314": ("GENCOST02-BP01", "GENCOST02-BP02"),
    # GENCOST 4: How do you optimize vector stores for cost?
    "REPO-315": ("GENCOST04-BP01",),
    # GENCOST 5: How do you optimize agent workflows for cost?
    "REPO-316": ("GENCOST05-BP01",),
    # GENSUS 1: How do you minimize the computational resources needed for training, c
    "REPO-317": ("GENSUS01-BP01", "GENSUS01-BP02"),
    # GENSUS 2: How can you optimize data processing and storage to minimize energy co
    "REPO-318": ("GENSUS02-BP01",),
    # GENSUS 3: How do you maintain model efficiency and resource optimization when wo
    "REPO-319": ("GENSUS03-BP01",),
    # RAIUC 1: How do you define the specific problem you are trying to solve?
    "REPO-320": ("RAIUC01-BP01", "RAIUC01-BP02"),
    # RAIUC 2: How will you identify the stakeholders of your use case?
    "REPO-321": ("RAIUC02-BP01", "RAIUC02-BP02"),
    # RAIUC 3: How will you refine your use case understanding without detailing the 
    "REPO-322": ("RAIUC03-BP01", "RAIUC03-BP02", "RAIUC03-BP03"),
    # RAIBR 1: How will you characterize intended benefits?
    "REPO-323": ("RAIBR01-BP01",),
    # RAIBR 2: How will you identify and categorize potential harmful events?
    "REPO-324": ("RAIBR02-BP01", "RAIBR02-BP02", "RAIBR02-BP03", "RAIBR02-BP04", "RAIBR02-BP05", "RAIBR02-BP06", "RAIBR02-BP07", "RAIBR02-BP08", "RAIBR02-BP09"),
    # RAIBR 3: How will you assess the risks posed by the potential harmful events?
    "REPO-325": ("RAIBR03-BP01", "RAIBR03-BP02", "RAIBR03-BP03", "RAIBR03-BP04"),
    # RAIRC 1: How will you define release criteria?
    "REPO-326": ("RAIRC01-BP01",),
    # RAIRC 2: How will you measure the properties tested by your release criteria?
    "REPO-327": ("RAIRC02-BP01", "RAIRC02-BP02", "RAIRC02-BP03"),
    # RAIRC 4: How will you set your release criteria thresholds?
    "REPO-328": ("RAIRC04-BP01", "RAIRC04-BP02", "RAIRC04-BP03"),
    # RAIDP 1: How will you identify which datasets are needed to evaluate, train, an
    "REPO-329": ("RAIDP01-BP01", "RAIDP01-BP02", "RAIDP01-BP03", "RAIDP01-BP04"),
    # RAIDP 2: How will you assess dataset quality?
    "REPO-330": ("RAIDP02-BP01", "RAIDP02-BP02", "RAIDP02-BP03", "RAIDP02-BP04"),
    # RAIDP 3: How will you identify and mitigate potential responsible AI issues in 
    "REPO-331": ("RAIDP03-BP01", "RAIDP03-BP02", "RAIDP03-BP03", "RAIDP03-BP04", "RAIDP03-BP05"),
    # RAIDP 4: How will you manage dataset access and versioning?
    "REPO-332": ("RAIDP04-BP01", "RAIDP04-BP02", "RAIDP04-BP03", "RAIDP04-BP04", "RAIDP04-BP05"),
    # RAISP 1: How will you design the core AI system architecture to meet your relea
    "REPO-333": ("RAISP01-BP01", "RAISP01-BP03"),
    # RAISP 2: How will you design the core AI system to meet the release criteria (b
    "REPO-334": ("RAISP02-BP01", "RAISP02-BP02", "RAISP02-BP03", "RAISP02-BP04", "RAISP02-BP05", "RAISP02-BP06", "RAISP02-BP07", "RAISP02-BP08", "RAISP02-BP09", "RAISP02-BP10"),
    # RAISP 4: How will you choose between different system configurations?
    "REPO-335": ("RAISP04-BP01",),
    # RAIER 1: How will you evaluate the AI system against your release criteria?
    "REPO-336": ("RAIER01-BP01", "RAIER01-BP02", "RAIER01-BP03"),
    # RAIER 2: How will you aggregate the release criteria results into a responsible
    "REPO-337": ("RAIER02-BP01", "RAIER02-BP02"),
    # RAIER 3: How will you address release criteria that are not met?
    "REPO-338": ("RAIER03-BP01", "RAIER03-BP02"),
    # RAIMON 2: How will you respond to feedback from monitoring?
    "REPO-339": ("RAIMON02-BP01",),
    # RAIMON 3: How will you decommission your AI system?
    "REPO-340": ("RAIMON03-BP01",),
    # AGENTOPS 3: How do you manage agent lifecycle and deployment processes?
    "REPO-341": ("AGENTOPS03-BP01", "AGENTOPS03-BP02", "AGENTOPS03-BP03", "AGENTOPS03-BP04"),
    # AGENTOPS 4: How do you establish tool integration and management practices?
    "REPO-342": ("AGENTOPS04-BP01", "AGENTOPS04-BP02", "AGENTOPS04-BP03"),
    # AGENTOPS 5: How do you implement comprehensive observability and monitoring for ag
    "REPO-343": ("AGENTOPS05-BP01", "AGENTOPS05-BP02", "AGENTOPS05-BP03", "AGENTOPS05-BP04", "AGENTOPS05-BP05"),
    # AGENTOPS 6: How do you implement testing, evaluation, and validation frameworks?
    "REPO-344": ("AGENTOPS06-BP01", "AGENTOPS06-BP02", "AGENTOPS06-BP03"),
    # AGENTOPS 7: How do you establish operational recovery and consumption monitoring?
    "REPO-345": ("AGENTOPS07-BP01", "AGENTOPS07-BP02", "AGENTOPS07-BP03", "AGENTOPS07-BP04"),
    # AGENTREL 1: How do I develop reliable agentic systems?
    "REPO-346": ("AGENTREL01-BP01", "AGENTREL01-BP02", "AGENTREL01-BP03", "AGENTREL01-BP04", "AGENTREL01-BP05"),
    # AGENTREL 2: How do you develop agentic systems that reliably execute tasks with pr
    "REPO-347": ("AGENTREL02-BP01", "AGENTREL02-BP02", "AGENTREL02-BP03", "AGENTREL02-BP04", "AGENTREL02-BP05"),
    # AGENTREL 3: How do you support agent memory and state remaining reliably accessibl
    "REPO-348": ("AGENTREL03-BP01", "AGENTREL03-BP02", "AGENTREL03-BP03", "AGENTREL03-BP04"),
    # AGENTREL 4: How do you orchestrate multi-agent systems to reliably execute tasks?
    "REPO-349": ("AGENTREL04-BP01", "AGENTREL04-BP02", "AGENTREL04-BP03", "AGENTREL04-BP04"),
    # AGENTREL 5: How do you implement reliable agent cognition that accesses the right 
    "REPO-350": ("AGENTREL05-BP01", "AGENTREL05-BP02", "AGENTREL05-BP03"),
    # AGENTREL 6: How do agents integrate effectively with existing systems without impa
    "REPO-351": ("AGENTREL06-BP01", "AGENTREL06-BP02", "AGENTREL06-BP03", "AGENTREL06-BP04", "AGENTREL06-BP05"),
    # AGENTREL 7: How do fault tolerant agent systems recover?
    "REPO-352": ("AGENTREL07-BP01", "AGENTREL07-BP02", "AGENTREL07-BP03"),
    # AGENTREL 8: How do agents determine when and where graceful degradation is appropr
    "REPO-353": ("AGENTREL08-BP01", "AGENTREL08-BP02", "AGENTREL08-BP03", "AGENTREL08-BP04"),
    # AGENTPERF 1: How do you plan strategically for agent performance and establish meas
    "REPO-354": ("AGENTPERF01-BP01", "AGENTPERF01-BP02", "AGENTPERF01-BP03"),
    # AGENTPERF 2: How do you optimize core agent processing and reasoning pipelines?
    "REPO-355": ("AGENTPERF02-BP01", "AGENTPERF02-BP02", "AGENTPERF02-BP03", "AGENTPERF02-BP04"),
    # AGENTPERF 3: How do you optimize memory management, context windows, and retrieval-
    "REPO-356": ("AGENTPERF03-BP01", "AGENTPERF03-BP02", "AGENTPERF03-BP03", "AGENTPERF03-BP04", "AGENTPERF03-BP05"),
    # AGENTPERF 4: How do you achieve efficient communication and protocol usage across a
    "REPO-357": ("AGENTPERF04-BP01", "AGENTPERF04-BP02", "AGENTPERF04-BP03"),
    # AGENTPERF 5: How do you optimize workflow orchestration and multi-agent collaborati
    "REPO-358": ("AGENTPERF05-BP01", "AGENTPERF05-BP02", "AGENTPERF05-BP03", "AGENTPERF05-BP04"),
    # AGENTPERF 6: How do you optimize tool integrations and framework usage for agent pe
    "REPO-359": ("AGENTPERF06-BP01", "AGENTPERF06-BP02", "AGENTPERF06-BP03"),
    # AGENTPERF 7: How do you manage multitenant performance isolation and optimize resou
    "REPO-360": ("AGENTPERF07-BP01", "AGENTPERF07-BP02"),
    # AGENTCOST 1: How do you optimize agent reasoning and execution costs?
    "REPO-361": ("AGENTCOST01-BP01", "AGENTCOST01-BP02", "AGENTCOST01-BP03", "AGENTCOST01-BP04"),
    # AGENTCOST 2: How do you optimize agent model invocation and token consumption costs
    "REPO-362": ("AGENTCOST02-BP01", "AGENTCOST02-BP02", "AGENTCOST02-BP03", "AGENTCOST02-BP04"),
    # AGENTCOST 3: How do you manage agent memory and state costs efficiently?
    "REPO-363": ("AGENTCOST03-BP01", "AGENTCOST03-BP02", "AGENTCOST03-BP03"),
    # AGENTCOST 4: How do you optimize agent tool invocation costs?
    "REPO-364": ("AGENTCOST04-BP01", "AGENTCOST04-BP02", "AGENTCOST04-BP03"),
    # AGENTCOST 5: How do you implement cost attribution?
    "REPO-365": ("AGENTCOST05-BP01", "AGENTCOST05-BP02", "AGENTCOST05-BP03", "AGENTCOST05-BP04"),
    # AGENTCOST 6: How do you optimize agent discovery, registry, and deployment costs?
    "REPO-366": ("AGENTCOST06-BP01", "AGENTCOST06-BP02", "AGENTCOST06-BP03"),
    # AGENTCOST 7: How do you establish agent cost governance and continuous optimization
    "REPO-367": ("AGENTCOST07-BP01", "AGENTCOST07-BP02", "AGENTCOST07-BP03"),
    # AGENTSUS 1: How do you build sustainable and repeatable frameworks for managing co
    "REPO-368": ("AGENTSUS01-BP01", "AGENTSUS01-BP02", "AGENTSUS01-BP03", "AGENTSUS01-BP04", "AGENTSUS01-BP05"),
    # AGENTSUS 2: How do I establish sustainable frameworks for agent dependencies?
    "REPO-369": ("AGENTSUS02-BP01", "AGENTSUS02-BP02", "AGENTSUS02-BP03", "AGENTSUS02-BP04"),
    # AGENTSUS 3: How do I establish durable patterns for agent interactions with users 
    "REPO-370": ("AGENTSUS03-BP01", "AGENTSUS03-BP02", "AGENTSUS03-BP03", "AGENTSUS03-BP04"),
}

# Every lens best practice now has a rule. A new catalog practice with no rule goes here until
# one covers it.
LENS_NOT_CHECKED: frozenset[str] = frozenset()
