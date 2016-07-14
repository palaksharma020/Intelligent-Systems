package com.security.evaluation.model;

public class AccPntsEffEvaluation {

	private double remAccPoints;
	private boolean autoToolsUsed;
	private boolean intDetectSys;
	private boolean revAudLogs;
	private boolean secIncDatabase;
	private double unauthAccPnts;
	private double unAccPntPer;

	public AccPntsEffEvaluation(double remAccPoints, boolean autoToolsUsed,
			boolean intDetectSys, boolean revAudLogs, boolean secIncDatabase,
			double unauthAccPnts) {
		super();
		this.remAccPoints = remAccPoints;
		this.autoToolsUsed = autoToolsUsed;
		this.intDetectSys = intDetectSys;
		this.revAudLogs = revAudLogs;
		this.secIncDatabase = secIncDatabase;
		this.unauthAccPnts = unauthAccPnts;
	}

	public boolean isAutoToolsUsed() {
		return autoToolsUsed;
	}

	public boolean isIntDetectSys() {
		return intDetectSys;
	}

	public double getRemAccPoints() {
		return remAccPoints;
	}

	public boolean isRevAudLogs() {
		return revAudLogs;
	}

	public boolean isSecIncDatabase() {
		return secIncDatabase;
	}

	public double getUnauthAccPnts() {
		return unauthAccPnts;
	}

	public double getUnAccPntPer() {
		if (autoToolsUsed)
			this.unAccPntPer = this.unauthAccPnts / this.remAccPoints;
		else
			this.unAccPntPer = 0;
		return this.unAccPntPer;
	}

	public String toString() {
		return remAccPoints + " " + autoToolsUsed + " " + intDetectSys + " "
				+ revAudLogs + "" + " " + secIncDatabase + " " + unauthAccPnts;
	}

}
