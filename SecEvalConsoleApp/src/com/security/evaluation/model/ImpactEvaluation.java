package com.security.evaluation.model;

public class ImpactEvaluation {

	private double secBudVal;
	private double infBudVal;
	private double impPercentage;

	public ImpactEvaluation(double secBudVal, double infBudVal) {
		super();
		this.secBudVal = secBudVal;
		this.infBudVal = infBudVal;
	}

	public double getSecBudVal() {
		return secBudVal;
	}

	public double getImpPercentage() {
		this.impPercentage = this.secBudVal / this.infBudVal;
		return this.impPercentage;
	}

	public double getInfBudVal() {
		return infBudVal;
	}

}
