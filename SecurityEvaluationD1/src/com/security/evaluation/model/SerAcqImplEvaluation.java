package com.security.evaluation.model;

public class SerAcqImplEvaluation {

	private double noOfActSerAcquisition;
	private double noOfActSerAcqWithSecSpec;
	private double serAcqImplPerc;

	public SerAcqImplEvaluation(double noOfActSerAcquisition,
			double noOfActSerAcqWithSecSpec) {
		super();
		this.noOfActSerAcquisition = noOfActSerAcquisition;
		this.noOfActSerAcqWithSecSpec = noOfActSerAcqWithSecSpec;
	}

	public double getNoOfActSerAcquisition() {
		return noOfActSerAcquisition;
	}

	public double getNoOfActSerAcqWithSecSpec() {
		return noOfActSerAcqWithSecSpec;
	}

	public double getSerAcqImplPerc() {
		this.serAcqImplPerc = this.noOfActSerAcqWithSecSpec / this.noOfActSerAcquisition;
		return this.serAcqImplPerc;
	}
}
