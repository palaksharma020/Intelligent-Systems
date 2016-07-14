package com.security.model;

public class UserInput {

	private String impact_eval_a1;
	private String impact_eval_a2;
	private String vuln_eval_a1;
	private String vuln_eval_a2;
	private String acpt_eval_a1;
	private String acpt_eval_a2;
	private String acpt_eval_a3;
	private String acpt_eval_a4;
	private String acpt_eval_a5;
	private String acpt_eval_a6;
	private String psi_eval_a1;
	private String psi_eval_a2;
	private String sacq_eval_a1;
	private String sacq_eval_a2;

	public UserInput(String impact_eval_a1, String impact_eval_a2,
			String vuln_eval_a1, String vuln_eval_a2, String acpt_eval_a1,
			String acpt_eval_a2, String acpt_eval_a3, String acpt_eval_a4,
			String acpt_eval_a5, String acpt_eval_a6, String psi_eval_a1,
			String psi_eval_a2, String sacq_eval_a1, String sacq_eval_a2) {
		super();
		this.impact_eval_a1 = impact_eval_a1;
		this.impact_eval_a2 = impact_eval_a2;
		this.vuln_eval_a1 = vuln_eval_a1;
		this.vuln_eval_a2 = vuln_eval_a2;
		this.acpt_eval_a1 = acpt_eval_a1;
		this.acpt_eval_a2 = acpt_eval_a2;
		this.acpt_eval_a3 = acpt_eval_a3;
		this.acpt_eval_a4 = acpt_eval_a4;
		this.acpt_eval_a5 = acpt_eval_a5;
		this.acpt_eval_a6 = acpt_eval_a6;
		this.psi_eval_a1 = psi_eval_a1;
		this.psi_eval_a2 = psi_eval_a2;
		this.sacq_eval_a1 = sacq_eval_a1;
		this.sacq_eval_a2 = sacq_eval_a2;
	}

	public String getAcpt_eval_a1() {
		return acpt_eval_a1;
	}

	public String getAcpt_eval_a2() {
		return acpt_eval_a2;
	}

	public String getAcpt_eval_a3() {
		return acpt_eval_a3;
	}

	public String getAcpt_eval_a4() {
		return acpt_eval_a4;
	}

	public String getAcpt_eval_a5() {
		return acpt_eval_a5;
	}

	public String getAcpt_eval_a6() {
		return acpt_eval_a6;
	}

	public String getImpact_eval_a1() {
		return impact_eval_a1;
	}

	public String getImpact_eval_a2() {
		return impact_eval_a2;
	}

	public String getVuln_eval_a1() {
		return vuln_eval_a1;
	}

	public String getVuln_eval_a2() {
		return vuln_eval_a2;
	}

	public String getPsi_eval_a1() {
		return psi_eval_a1;
	}

	public String getPsi_eval_a2() {
		return psi_eval_a2;
	}

	public String getSacq_eval_a1() {
		return sacq_eval_a1;
	}

	public String getSacq_eval_a2() {
		return sacq_eval_a2;
	}

	@Override
	public String toString() {
		return "UserInput [impact_eval_a1=" + impact_eval_a1
				+ ", impact_eval_a2=" + impact_eval_a2 + ", vuln_eval_a1="
				+ vuln_eval_a1 + ", vuln_eval_a2=" + vuln_eval_a2
				+ ", acpt_eval_a1=" + acpt_eval_a1 + ", acpt_eval_a2="
				+ acpt_eval_a2 + ", acpt_eval_a3=" + acpt_eval_a3
				+ ", acpt_eval_a4=" + acpt_eval_a4 + ", acpt_eval_a5="
				+ acpt_eval_a5 + ", acpt_eval_a6=" + acpt_eval_a6
				+ ", psi_eval_a1=" + psi_eval_a1 + ", psi_eval_a2="
				+ psi_eval_a2 + ", sacq_eval_a1=" + sacq_eval_a1
				+ ", sacq_eval_a2=" + sacq_eval_a2 + "]";
	}

}
