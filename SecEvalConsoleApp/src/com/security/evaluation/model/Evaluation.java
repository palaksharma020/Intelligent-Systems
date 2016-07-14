package com.security.evaluation.model;

import java.text.DecimalFormat;

public class Evaluation {

	private final float percentage;
	private final String description;
	private final String recommendations;
	private static DecimalFormat formatter = new DecimalFormat("0.00%");

	public Evaluation(String aDescription, float apercentage,
			String arecommendations) {
		description = aDescription;
		percentage = apercentage;
		recommendations = arecommendations;
	}

	public String getRecommendations() {
		return recommendations;
	}

	public float getPercentage() {
		return percentage*100;
	}

	public String getDescription() {
		return description;
	}

	public String toString() {
		return description + " " + formatter.format(percentage)
				+ " "+recommendations;
	}

}
