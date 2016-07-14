package com.security.evaluation.model;

public class PersSecImplEvaluation {

	private double noOfScrndPersonnel;
	private double noOfAuthPersonnel;
	private double perSecImplPerc;

	public PersSecImplEvaluation(double noOfScrndPersonnel,
			double noOfAuthPersonnel) {
		super();
		this.noOfScrndPersonnel = noOfScrndPersonnel;
		this.noOfAuthPersonnel = noOfAuthPersonnel;
	}

	public double getNoOfScrndPersonnel() {
		return noOfScrndPersonnel;
	}

	public double getNoOfAuthPersonnel() {
		return noOfAuthPersonnel;
	}

	public double getPerSecImplPerc() {
		this.perSecImplPerc = this.noOfScrndPersonnel / this.noOfAuthPersonnel;
		return this.perSecImplPerc;
	}
}
