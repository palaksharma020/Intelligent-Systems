package com.security.evaluation.demo;

import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;

import com.security.evaluation.enums.InputFieldDescriptionEnum;
import com.security.evaluation.model.AccPntsEffEvaluation;
import com.security.evaluation.model.Evaluation;
import com.security.evaluation.model.ImpactEvaluation;
import com.security.evaluation.model.OverallSecurityEvaluation;
import com.security.evaluation.model.PersSecImplEvaluation;
import com.security.evaluation.model.SerAcqImplEvaluation;
import com.security.evaluation.model.VulnEffEvaluation;
import com.security.evaluation.security.SecurityEngine;
import jess.JessException;

public class Demo {

	public static void main(String[] args) {

		Scanner scan = null;
		try {
			scan = new Scanner(System.in);

			if (scan != null) {

				/*
				 * Measure 1: Security Budget (program-level) ; Measure Type -
				 * Impact
				 */

				ImpactEvaluation impactEvaluationObj = getImpactEvalObject(scan);

				/*
				 * Measure 2: Vulnerability Management (program-level); Measure
				 * Type - Effectiveness/Efficiency
				 */

				VulnEffEvaluation VulnEffEvalObj = getVulEffEvalObject(scan);

				/*
				 * Measure 3: Access Control (AC) (system-level); Measure Type -
				 * Effectiveness/Efficiency
				 */

				AccPntsEffEvaluation accPntsEffEvalObj = getAccPntsEffEvalObject(scan);

				/*
				 * Measure 4: Personnel Security (PS) (program level and system
				 * level); Measure Type - Implementation
				 */

				PersSecImplEvaluation persSecImplEvaluation = getPerSecImplEvalObject(scan);

				/*
				 * Measure 5: System and Services Acquisition (SA)
				 * (program-level and system-level); Measure Type -
				 * Implementation
				 */

				SerAcqImplEvaluation serAcqImplEvaluation = getSerAcqImplEvalObject(scan);

				/*
				 * ##############################################################
				 * #
				 * #############################################################
				 */

				/* Create instance of engine object */
				SecurityEngine secEngine = new SecurityEngine();

				System.out
						.println(InputFieldDescriptionEnum.EVAL_RESULT_HEADING
								.getInputValue());
				System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
						.getInputValue());

				/* Get impact evaluation in percentage as per rules. */
				getEvaluationforImpact(secEngine, impactEvaluationObj);

				/*
				 * Get vulnerability efficiency evaluation in percentage as per
				 * rules.
				 */
				getEvaluationforVulnEfficiency(secEngine, VulnEffEvalObj);

				/*
				 * Get access point efficiency evaluation in percentage as per
				 * rules.
				 */
				if (null != accPntsEffEvalObj)
					getEvaluationforAccPntEfficiency(secEngine,
							accPntsEffEvalObj);

				/*
				 * Get personnel security implementation evaluation in
				 * percentage as per rules.
				 */
				getEvaluationforPersSecImpl(secEngine, persSecImplEvaluation);

				/*
				 * Get service security acquisition implementation evaluation in
				 * percentage as per rules.
				 */
				getEvaluationforSerAcqImpl(secEngine, serAcqImplEvaluation);

				/*
				 * Get overall security evaluation in percentage as per rules.
				 */
				List<Evaluation> overAllEvalList = getOverallSecurityEvaluation(
						secEngine, impactEvaluationObj, VulnEffEvalObj,
						accPntsEffEvalObj, persSecImplEvaluation,
						serAcqImplEvaluation);

				for (Evaluation eval : overAllEvalList) {
					if(!eval.getDescription().equals("Recommendations"))
					System.out.println(eval.getDescription()+""+eval.getPercentage()+"%");
				}
				System.out.println(InputFieldDescriptionEnum.STARS
						.getInputValue());
				System.out.println(InputFieldDescriptionEnum.STARS
						.getInputValue());

				List<String> allRecommList = new ArrayList<String>();

				for (Evaluation eval : overAllEvalList) {
					if (!eval.getRecommendations().equals(" ")) {
						String rec = eval.getRecommendations();
						String[] arr = rec.split("#");
						for (String s : arr) {
							if (s.length()!=0) {
								allRecommList.add(s);
							}
						}
					}

				}
				System.out.println("RECOMMENDATIONS");
				System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
						.getInputValue());
				for (String a : allRecommList)
					System.out.println(a);
				System.out.println(InputFieldDescriptionEnum.STARS
						.getInputValue());
				System.out.println(InputFieldDescriptionEnum.STARS
						.getInputValue());
			}
		} catch (NumberFormatException nfe) {
			System.out
					.println("Please enter numeric values.The evaluation will start from begining.");
			main(args);
		} catch (InputMismatchException ime) {
			System.out
					.println("Please enter numeric values.The evaluation will start from begining.");
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());
			System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
			System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());

			main(args);
		} catch (JessException e) {
			e.printStackTrace();
			System.out.println("Some Jess Error.");
		} finally {
			if (scan != null)
				scan.close();
		}
	}

	private static List<Evaluation> getOverallSecurityEvaluation(
			SecurityEngine secEngine, ImpactEvaluation impactEvaluationObj,
			VulnEffEvaluation vulnEffEvalObj,
			AccPntsEffEvaluation accPntsEffEvalObj,
			PersSecImplEvaluation persSecImplEvaluation,
			SerAcqImplEvaluation serAcqImplEvaluation) {

		Iterator overallsecEvalItr;
		List<Evaluation> overAllEvalList = new ArrayList<Evaluation>();

		OverallSecurityEvaluation overallSecEvalObj = new OverallSecurityEvaluation(
				impactEvaluationObj.getImpPercentage(),
				vulnEffEvalObj.getVulPercentage(), accPntsEffEvalObj.getUnAccPntPer(),
				persSecImplEvaluation.getPerSecImplPerc(),
				serAcqImplEvaluation.getSerAcqImplPerc());

		try {
			overallsecEvalItr = secEngine.run(overallSecEvalObj);
			while (overallsecEvalItr.hasNext()) {
				// System.out.println(overallsecEvalItr.next());
				overAllEvalList.add((Evaluation) overallsecEvalItr.next());
			}

		} catch (JessException e) {
			e.printStackTrace();
		}
		return overAllEvalList;
	}

	private static SerAcqImplEvaluation getSerAcqImplEvalObject(Scanner scan) {

		List<Double> SerAcqImplEvalInputList = getInputForSerAcqImplEvaluation(scan);

		/*
		 * Q1. How many active service acquisition contracts does the
		 * organization have?
		 */

		double noOfActSerAcquisition = SerAcqImplEvalInputList.get(0);

		/*
		 * Q2. How many active service acquisition contracts include security
		 * requirements and specifications (SA-4)?
		 */

		double noOfActSerAcqWithSecSpec = SerAcqImplEvalInputList.get(1);

		/* create object of PersSecImpEvaluation class */
		SerAcqImplEvaluation serAcqImplEvaluation = new SerAcqImplEvaluation(
				noOfActSerAcquisition, noOfActSerAcqWithSecSpec);

		return serAcqImplEvaluation;
	}

	private static PersSecImplEvaluation getPerSecImplEvalObject(Scanner scan) {

		List<Double> persSecImplEvalInputList = getInputForPersSecImplEvaluation(scan);

		/*
		 * Q1. How many individuals have been granted access to organizational
		 * information and information systems (AC-2)?
		 */

		double noOfAuthPersonnel = persSecImplEvalInputList.get(0);

		/*
		 * Q2. What is the number of individuals who have completed personnel
		 * screening (PS-3)?
		 */

		double noOfScrndPersonnel = persSecImplEvalInputList.get(1);

		/* create object of PersSecImpEvaluation class */
		PersSecImplEvaluation persSecImplEvaluation = new PersSecImplEvaluation(
				noOfScrndPersonnel, noOfAuthPersonnel);

		return persSecImplEvaluation;
	}

	private static List<Double> getInputForSerAcqImplEvaluation(Scanner scan) {

		List<Double> SerAcqImplEvalInputList = new ArrayList<Double>();

		System.out.println(InputFieldDescriptionEnum.SER_ACQ_IMPL_EVAL_HEADING
				.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.SER_ACQ_IMPL_EVAL_INPUT_1
				.getInputValue());
		Double noOfActSerAcquisition = scan.nextDouble();
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.SER_ACQ_IMPL_EVAL_INPUT_2
				.getInputValue());
		Double noOfActSerAcqWithSecSpec = scan.nextDouble();
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
		System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		SerAcqImplEvalInputList.add(noOfActSerAcquisition);
		SerAcqImplEvalInputList.add(noOfActSerAcqWithSecSpec);

		return SerAcqImplEvalInputList;

	}

	private static List<Double> getInputForPersSecImplEvaluation(Scanner scan) {

		List<Double> persSecImplEvalInputList = new ArrayList<Double>();

		System.out.println(InputFieldDescriptionEnum.PERS_SEC_IMPL_EVAL_HEADING
				.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.PERS_SEC_IMPL_EVAL_INPUT_1
				.getInputValue());
		Double noOfAuthPersonnel = scan.nextDouble();
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.PERS_SEC_IMPL_EVAL_INPUT_2
				.getInputValue());
		Double noOfScrndPersonnel = scan.nextDouble();
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
		System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		persSecImplEvalInputList.add(noOfAuthPersonnel);
		persSecImplEvalInputList.add(noOfScrndPersonnel);

		return persSecImplEvalInputList;
	}

	private static AccPntsEffEvaluation getAccPntsEffEvalObject(Scanner scan) {

		List accPntsEffEvalInputList = getInputForAccPntsEffEvaluation(scan);
		AccPntsEffEvaluation accPntsEffEvalObj = null;
		/*
		 * Q1. Does the organization use automated tools to maintain an
		 * up-to-that identifies all remote access points (CM-2)?
		 */

		boolean autoToolsUsed = (boolean) accPntsEffEvalInputList.get(0);

		/*
		 * Q2. How many remote access points exist in the organization’s
		 * network?
		 */
		if (autoToolsUsed) {
			double remAccPoints = (double) (accPntsEffEvalInputList.get(1));

			/*
			 * Q3. Does the organization employ Intrusion Detection Systems
			 * (IDS) to monitor traffic traversing remote access points (SI-4)?
			 */

			boolean intDetectSys = (boolean) accPntsEffEvalInputList.get(2);

			/*
			 * Q4. Does the organization collect and review audit logs
			 * associated with all remote access points (AU-6)?
			 */

			boolean revAudLogs = (boolean) accPntsEffEvalInputList.get(3);

			/*
			 * Q5. Does the organization maintain a security incident database
			 * that identifies standardized incident categories for each
			 * incident (IR-5)?
			 */

			boolean secIncDatabase = (boolean) accPntsEffEvalInputList.get(4);

			/*
			 * Q6. Based on reviews of the incident database, IDS logs and
			 * alerts, and/or appropriate remote access point log files, how
			 * many access points have been used to gain unauthorized access
			 * within the reporting period?
			 */

			double unauthAccPnts = (double) accPntsEffEvalInputList.get(5);

			/* create object of AccPntsEffEvaluation class */
			accPntsEffEvalObj = new AccPntsEffEvaluation(remAccPoints,
					autoToolsUsed, intDetectSys, revAudLogs, secIncDatabase,
					unauthAccPnts);

		} else {
			accPntsEffEvalObj = new AccPntsEffEvaluation(0,
					autoToolsUsed, false, false, false,
					0);

		}

		return accPntsEffEvalObj;
	}

	private static VulnEffEvaluation getVulEffEvalObject(Scanner scan) {

		List<Double> vulEffEvalInputList = getInputForVulEffEvaluation(scan);

		/*
		 * Q1. Number of high vulnerabilities identified across the enterprise
		 * during the time period (RA-5)?
		 */
		double idenHighVuln = vulEffEvalInputList.get(0);

		/*
		 * Q2. Number of high vulnerabilities mitigated across the enterprise
		 * during the time period (RA-5)?
		 */
		double mitHighVuln = vulEffEvalInputList.get(1);

		/* create object of VulnEffEvaluation class */
		VulnEffEvaluation VulnEffEvalObj = new VulnEffEvaluation(mitHighVuln,
				idenHighVuln);
		return VulnEffEvalObj;
	}

	private static ImpactEvaluation getImpactEvalObject(Scanner scan) {

		List<Double> impactEvalInputList = getInputForImpactEvaluation(scan);

		/*
		 * Q1. What is the total information security budget across all agency
		 * systems (SA-2)?
		 */
		double secBudVal = impactEvalInputList.get(0);

		/*
		 * Q2. What is the total information technology budget across all agency
		 * systems (SA-2)?
		 */
		double infBudVal = impactEvalInputList.get(1);

		/* create object of Impact Evaluation class */
		ImpactEvaluation impactEvaluationObj = new ImpactEvaluation(secBudVal,
				infBudVal);
		return impactEvaluationObj;
	}

	@SuppressWarnings("unchecked")
	private static List getInputForAccPntsEffEvaluation(Scanner scan) {

		@SuppressWarnings("rawtypes")
		List accPntsEffEvalInputList = new ArrayList<>();

		System.out.println(InputFieldDescriptionEnum.ACC_PNTS_EFF_EVAL_HEADING
				.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.ACC_PNTS_EFF_EVAL_INPUT_1
				.getInputValue());
		String autoToolsUsedString = scan.next();
		Boolean autoToolsUsed = convertStringToBoolean(autoToolsUsedString);
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		if (autoToolsUsed) {
			System.out
					.println(InputFieldDescriptionEnum.ACC_PNTS_EFF_EVAL_INPUT_2
							.getInputValue());
			Double remAccPoints = scan.nextDouble();
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());

			System.out
					.println(InputFieldDescriptionEnum.ACC_PNTS_EFF_EVAL_INPUT_3
							.getInputValue());
			String intDetectSysString = scan.next();
			Boolean intDetectSys = convertStringToBoolean(intDetectSysString);
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());

			System.out
					.println(InputFieldDescriptionEnum.ACC_PNTS_EFF_EVAL_INPUT_4
							.getInputValue());
			String revAudLogsString = scan.next();
			Boolean revAudLogs = convertStringToBoolean(revAudLogsString);
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());

			System.out
					.println(InputFieldDescriptionEnum.ACC_PNTS_EFF_EVAL_INPUT_5
							.getInputValue());
			String secIncDatabaseString = scan.next();
			Boolean secIncDatabase = convertStringToBoolean(secIncDatabaseString);
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());

			System.out
					.println(InputFieldDescriptionEnum.ACC_PNTS_EFF_EVAL_INPUT_6
							.getInputValue());
			Double unauthAccPnts = scan.nextDouble();
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());

			System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
			System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());

			accPntsEffEvalInputList.add(autoToolsUsed);
			accPntsEffEvalInputList.add(remAccPoints);
			accPntsEffEvalInputList.add(intDetectSys);
			accPntsEffEvalInputList.add(revAudLogs);
			accPntsEffEvalInputList.add(secIncDatabase);
			accPntsEffEvalInputList.add(unauthAccPnts);
		} else {
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());
			System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
			System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
			System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
					.getInputValue());

			accPntsEffEvalInputList.add(autoToolsUsed);
		}
		return accPntsEffEvalInputList;

	}

	private static Boolean convertStringToBoolean(String autoToolsUsedString) {
		Boolean boolVal = false;
		if ((autoToolsUsedString.equals("Y"))
				|| (autoToolsUsedString.equals("y"))) {
			boolVal = true;
		}
		return boolVal;
	}

	private static List<Double> getInputForVulEffEvaluation(Scanner scan) {

		System.out.println(InputFieldDescriptionEnum.VUL_EFF_EVAL_HEADING
				.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.VUL_EFF_EVAL_INPUT_1
				.getInputValue());
		Double idenHighVuln = scan.nextDouble();
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.VUL_EFF_EVAL_INPUT_2
				.getInputValue());
		Double mitHighVuln = scan.nextDouble();
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
		System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		List<Double> impactEvalInputList = new ArrayList<Double>();
		impactEvalInputList.add(idenHighVuln);
		impactEvalInputList.add(mitHighVuln);

		return impactEvalInputList;
	}

	private static List<Double> getInputForImpactEvaluation(Scanner scan) {

		// read line from the user input

		System.out.println(InputFieldDescriptionEnum.IMPACT_EVAL_HEADING
				.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.IMPACT_EVAL_INPUT_1
				.getInputValue());
		Double secBudString = scan.nextDouble();
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.IMPACT_EVAL_INPUT_2
				.getInputValue());
		Double infBudString = scan.nextDouble();
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
		System.out.println(InputFieldDescriptionEnum.STARS.getInputValue());
		System.out.println(InputFieldDescriptionEnum.EMPTY_STRING
				.getInputValue());

		List<Double> impactEvalInputList = new ArrayList<Double>();
		impactEvalInputList.add(secBudString);
		impactEvalInputList.add(infBudString);

		return impactEvalInputList;
	}

	private static void getEvaluationforSerAcqImpl(SecurityEngine secEngine,
			SerAcqImplEvaluation serAcqImplEvaluation) {

		Iterator serAcqImplEvalItr;
		try {
			serAcqImplEvalItr = secEngine.run(serAcqImplEvaluation);

			while (serAcqImplEvalItr.hasNext()) {
				System.out.println(serAcqImplEvalItr.next());

			}
		} catch (JessException e) {
			e.printStackTrace();
		}
	}

	private static void getEvaluationforPersSecImpl(SecurityEngine secEngine,
			PersSecImplEvaluation persSecImplEvaluation) {

		Iterator persSecImplEvalItr;
		try {
			persSecImplEvalItr = secEngine.run(persSecImplEvaluation);

			while (persSecImplEvalItr.hasNext()) {
				System.out.println(persSecImplEvalItr.next());

			}
		} catch (JessException e) {
			e.printStackTrace();
		}
	}

	private static void getEvaluationforAccPntEfficiency(
			SecurityEngine secEngine, AccPntsEffEvaluation accPntsEffEvalObj) {

		Iterator accPntsEffEvalItr;
		try {
			accPntsEffEvalItr = secEngine.run(accPntsEffEvalObj);

			while (accPntsEffEvalItr.hasNext()) {
				System.out.println(accPntsEffEvalItr.next());

			}
		} catch (JessException e) {
			e.printStackTrace();
		}
	}

	private static void getEvaluationforVulnEfficiency(
			SecurityEngine secEngine, VulnEffEvaluation vulnEffEvalObj) {

		Iterator vulEffEvalItr;
		try {
			vulEffEvalItr = secEngine.run(vulnEffEvalObj);

			while (vulEffEvalItr.hasNext()) {
				System.out.println(vulEffEvalItr.next());

			}
		} catch (JessException e) {
			e.printStackTrace();
		}
	}

	private static Evaluation getEvaluationforImpact(SecurityEngine secEngine,
			ImpactEvaluation impEvalObj) {
		Evaluation impactEval = null;
		Iterator impactEvalItr;
		try {
			impactEvalItr = secEngine.run(impEvalObj);

			while (impactEvalItr.hasNext()) {
				System.out.println(impactEvalItr.next());

			}
		} catch (JessException e) {
			e.printStackTrace();
		}
		return impactEval;
	}

}
