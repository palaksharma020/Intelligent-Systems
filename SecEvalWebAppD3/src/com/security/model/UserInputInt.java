package com.security.model;

public class UserInputInt {

	private double impact_eval_a1;
	private double impact_eval_a2;
	private double vuln_eval_a1;
	private double vuln_eval_a2;
	private String acpt_eval_a1;
	private double acpt_eval_a2;
	private String acpt_eval_a3;
	private String acpt_eval_a4;
	private String acpt_eval_a5;
	private double acpt_eval_a6;
	private double psi_eval_a1;
	private double psi_eval_a2;
	private double sacq_eval_a1;
	private double sacq_eval_a2;

	public UserInputInt(String impact_eval_a1, String impact_eval_a2,
			String vuln_eval_a1, String vuln_eval_a2, String acpt_eval_a1,
			String acpt_eval_a2, String acpt_eval_a3, String acpt_eval_a4,
			String acpt_eval_a5, String acpt_eval_a6, String psi_eval_a1,
			String psi_eval_a2, String sacq_eval_a1, String sacq_eval_a2) {
		super();
		this.impact_eval_a1 = Double.parseDouble(impact_eval_a1);
		this.impact_eval_a2 = Double.parseDouble(impact_eval_a2);
		this.vuln_eval_a1 = Double.parseDouble(vuln_eval_a1);
		this.vuln_eval_a2 = Double.parseDouble(vuln_eval_a2);
		this.acpt_eval_a1 = acpt_eval_a1;
		this.acpt_eval_a2 = Double.parseDouble(acpt_eval_a2);
		this.acpt_eval_a3 = acpt_eval_a3;
		this.acpt_eval_a4 = acpt_eval_a4;
		this.acpt_eval_a5 = acpt_eval_a5;
		this.acpt_eval_a6 = Double.parseDouble(acpt_eval_a6);
		this.psi_eval_a1 = Double.parseDouble(psi_eval_a1);
		this.psi_eval_a2 = Double.parseDouble(psi_eval_a2);
		this.sacq_eval_a1 = Double.parseDouble(sacq_eval_a1);
		this.sacq_eval_a2 = Double.parseDouble(sacq_eval_a2);
	}

	public double getImpact_eval_a1() {
		return impact_eval_a1;
	}

	public double getImpact_eval_a2() {
		return impact_eval_a2;
	}

	public double getVuln_eval_a1() {
		return vuln_eval_a1;
	}

	public double getVuln_eval_a2() {
		return vuln_eval_a2;
	}

	public double getPsi_eval_a1() {
		return psi_eval_a1;
	}

	public double getPsi_eval_a2() {
		return psi_eval_a2;
	}

	public double getSacq_eval_a1() {
		return sacq_eval_a1;
	}

	public double getSacq_eval_a2() {
		return sacq_eval_a2;
	}

	public String getAcpt_eval_a1() {
		return acpt_eval_a1;
	}

	public double getAcpt_eval_a2() {
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

	public double getAcpt_eval_a6() {
		return acpt_eval_a6;
	}

	@Override
	public String toString() {
		return "UserInputInt [impact_eval_a1=" + impact_eval_a1
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
