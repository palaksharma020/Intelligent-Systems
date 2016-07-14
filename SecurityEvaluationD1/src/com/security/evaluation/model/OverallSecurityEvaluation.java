package com.security.evaluation.model;

public class OverallSecurityEvaluation {

	private double impPercentage;
	private double vulPercentage;
	private double unAccPntPer;
	private double perSecImplPerc;
	private double serAcqImplPerc;
	private double overallSecPer;

	public OverallSecurityEvaluation(double impPercentage,
			double vulPercentage, double unAccPntPer, double perSecImplPerc,
			double serAcqImplPerc) {
		super();
		this.impPercentage = impPercentage;
		this.vulPercentage = vulPercentage;
		if(unAccPntPer ==0){
			this.unAccPntPer = 0;
		}
		else{
			this.unAccPntPer = 1 - unAccPntPer;
		}
		this.perSecImplPerc = perSecImplPerc;
		this.serAcqImplPerc = serAcqImplPerc;
	}

	public double getImpPercentage() {
		return impPercentage;
	}

	public double getVulPercentage() {
		return vulPercentage;
	}

	public double getUnAccPntPer() {
		return unAccPntPer;
	}

	public double getPerSecImplPerc() {
		return perSecImplPerc;
	}

	public double getSerAcqImplPerc() {
		return serAcqImplPerc;
	}

	public double getOverallSecPer() {

		if (this.impPercentage > 1) {
			this.impPercentage = 0;
		}
		if (this.vulPercentage > 1) {
			this.vulPercentage = 0;
		}
		if (this.perSecImplPerc > 1) {
			this.perSecImplPerc = 0;
		}
		if (this.serAcqImplPerc > 1) {
			this.serAcqImplPerc = 0;
		}
		if (this.unAccPntPer < 0) {
			this.unAccPntPer = 0;
		}
		
		this.overallSecPer = (this.impPercentage + this.vulPercentage
				+ this.unAccPntPer + this.perSecImplPerc + this.serAcqImplPerc) / 5;
		
		return this.overallSecPer;
	}

}
