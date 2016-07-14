package com.security.enums;

public enum InputFieldDescriptionEnum {

	IMPACT_EVAL_HEADING("Enter Impact Evaluation Information"),
	
	IMPACT_EVAL_INPUT_1(
			"Q1. What is the total information security budget across all agency systems ?"),

	IMPACT_EVAL_INPUT_2(
			"Q2. What is the total information technology budget across all agency systems ?"),

	VUL_EFF_EVAL_HEADING(
			"Enter Vulnerability Efficiency Evaluation Information"),

	VUL_EFF_EVAL_INPUT_1(
			"Q1. Number of high vulnerabilities identified across the enterprise during the time period"),

	VUL_EFF_EVAL_INPUT_2(
			"Q2. Number of high vulnerabilities mitigated across the enterprise during the time period"),

	ACC_PNTS_EFF_EVAL_HEADING(
			"Enter Access Points Efficiency Evaluation Information"), 
			
	ACC_PNTS_EFF_EVAL_INPUT_1(
			"Q1. Does the organization use automated tools to maintain an up-to-that identifies all remote access points (Y/N)?"), 
			
    ACC_PNTS_EFF_EVAL_INPUT_2(
			"Q2. How many remote access points exist in the organization’s network ?"), 
			
	ACC_PNTS_EFF_EVAL_INPUT_3(
			"Q3. Does the organization employ Intrusion Detection Systems (IDS) to monitor traffic traversing remote access points (Y/N)?"), 
			
   ACC_PNTS_EFF_EVAL_INPUT_4(
			"Q4. Does the organization collect and review audit logs associated with all remote access points (Y/N)?"),
			
   ACC_PNTS_EFF_EVAL_INPUT_5("Q5. Does the organization maintain a security incident database that identifies standardized incident categories for each incident (Y/N)?"), 
			
   ACC_PNTS_EFF_EVAL_INPUT_6(
			"Q6. Based on reviews of the incident database, IDS logs and alerts, and/or appropriate remote access point log files, how many access points have been used to gain unauthorized access within the reporting period?"), 
			
   PERS_SEC_IMPL_EVAL_HEADING("Enter Personnel Security Implementation Evaluation Information"),
   
   PERS_SEC_IMPL_EVAL_INPUT_1("Q1. How many individuals have been granted access to organizational information and information systems ?"),
   
   PERS_SEC_IMPL_EVAL_INPUT_2("Q2. What is the number of individuals who have completed personnel screening ?"),
   
   SER_ACQ_IMPL_EVAL_HEADING("Enter Service Acquisition Implementation Evaluation Information"),
   
   SER_ACQ_IMPL_EVAL_INPUT_1("Q1. How many active service acquisition contracts does the organization have?"),
   
   SER_ACQ_IMPL_EVAL_INPUT_2("Q2. How many active service acquisition contracts include security requirements and specifications (SA-4)?"),
   
   EVAL_RESULT_HEADING("EVALUATION RESULT"),
   
   EMPTY_STRING(""),
   
   STARS("*********************************************************************************************");

	private final String inputValue;

	private InputFieldDescriptionEnum(String inputValue) {
		this.inputValue = inputValue;
	}

	public String getInputValue() {
		return this.inputValue;
	}
}
