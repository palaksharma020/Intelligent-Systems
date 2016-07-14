package com.security.model;

public class VulnEffEvaluation {

	private double mitHighVuln;
	private double idenHighVuln;
	private double vulPercentage;

	public VulnEffEvaluation(double mitHighVuln, double idenHighVuln) {
		super();
		this.mitHighVuln = mitHighVuln;
		this.idenHighVuln = idenHighVuln;
	}

	public double getMitHighVuln() {
		return mitHighVuln;
	}

	public double getVulPercentage() {
		if (this.idenHighVuln == 0)
			this.idenHighVuln = 1;
		this.vulPercentage = this.mitHighVuln / this.idenHighVuln;
		return this.vulPercentage;
	}

	public double getIdenHighVuln() {
		return idenHighVuln;
	}

	public void setVulPercentage(double vulPercentage) {
		this.vulPercentage = vulPercentage;
	}

}
