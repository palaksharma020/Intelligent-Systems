package com.security.model;

import java.text.DecimalFormat;

public class Evaluation {

	private final float percentage;
	private final String metricDesc;
	private final String evalResDesc;
	private final String desiredEvalResDesc;
	private final String recommendations;

	private static DecimalFormat formatter = new DecimalFormat("0.00%");

	public Evaluation(String metricDesc, String evalResDesc, float percentage,
			String desiredEvalResDesc, String recommendations) {
		super();
		this.metricDesc = metricDesc;
		this.evalResDesc = evalResDesc;
		this.desiredEvalResDesc = desiredEvalResDesc;
		this.percentage = percentage *100;
		this.recommendations = recommendations;
	}

	public String getRecommendations() {
		return recommendations;
	}

	public float getPercentage() {
		return percentage * 100;
	}

	public String getMetricDesc() {
		return metricDesc;
	}

	public String getEvalResDesc() {
		return evalResDesc;
	}

	public String getDesiredEvalResDesc() {
		return desiredEvalResDesc;
	}

	@Override
	public String toString() {
		return "Evaluation [percentage=" + formatter.format(percentage)
				+ ", metricDesc=" + metricDesc + ", evalResDesc=" + evalResDesc
				+ ", desiredEvalResDesc=" + desiredEvalResDesc
				+ ", recommendations=" + recommendations + "]";
	}
}
