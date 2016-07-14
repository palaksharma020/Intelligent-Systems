'use strict';

App
		.controller(
				'SecurityController',
				[
						'$http',
						'$scope',
						function($http, $scope) {
							$http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
							var self = this;

							self.user_inputs = {
								a1 : null,
								a2 : null,
								b1 : null,
								b2 : null,
								c1 : '',
								c2 : 1,
								c3 : 0,
								c4 : 1,
								c5 : 0,
								c6 : 1,
								c7 : 0
							};

							self.evaluations = [];
							self.recommendations = [];

							self.evaluation1 = {
								metricDesc : 'Security Budget Impact Evaluation',
								evalResDesc : 'Cannot Determine. Please enter valid values in the above form.',
								percentage : 0,
								desiredEvalResDesc : '90 to 100',
								recommendations : ' '
							};

							self.evaluation2 = {
								metricDesc : 'Vulnerability Efficiency Evaluation',
								evalResDesc : 'Cannot Determine. Please enter valid values in the above form.',
								percentage : 0,
								desiredEvalResDesc : '90 to 100',
								recommendations : ' '
							};

							self.evaluation3 = {
								metricDesc : 'Personnel Security Implementation Evaluation',
								evalResDesc : 'Cannot Determine. Please enter valid values in the above form.',
								percentage : 0,
								desiredEvalResDesc : '90 to 100',
								recommendations : ' '
							};
							self.evaluation4 = {
								metricDesc : 'q4',
								evalResDesc : '40',
								percentage : 40,
								desiredEvalResDesc : '90',
								recommendations : ' '
							};


							self.recommendations1 = {
							a1 : 'Impact Evaluation : No recommendation available.Please enter valid value in above form.',
							};
							self.recommendations2 = {
							a1 : 'Vulnerability Evaluation : No recommendation available.Please enter valid value in above form.'
							};
							self.recommendations3 = {
							a1 : 'Personnel Security Evaluation : No recommendation available.Please enter valid value in above form.'
							};
							self.eval = {
								metricDesc : 'Security Budget Impact Evaluation',
								evalResDesc : 'Cannot Determine. Please enter valid values in the above form.',
								percentage : 0,
								desiredEvalResDesc : '90 to 100',
								recommendations : ''
							};
							$scope.evalList = [ {
								metricDesc : '',
								evalResDesc : '',
								percentage : 0,
								desiredEvalResDesc : '',
								recommendations : ''
							} ];

							self.sendPost = function() {
								self.evaluations = [];
								self.recommendations = [];
								$scope.showPanel = true;

								var impPer = 0;
								var vulnPer = 0;

								// Logic for rule implementation

								if (self.user_inputs.a1 == 0) {
									self.user_inputs.a1 = 1;
								}
								if (self.user_inputs.b1 == 0) {
									self.user_inputs.b1 = 1;
								}

								impPer = (self.user_inputs.a2 / self.user_inputs.a1) * 100;
								vulnPer = (self.user_inputs.b2 / self.user_inputs.b1) * 100;
								console.log(impPer);

								// Logic for rule implementation Metric 1 : Security Budget Impact Evaluation

								if (impPer > 90 && impPer <= 100) {
									self.eval.metricDesc = 'Security Budget Impact Evaluation';
									self.eval.evalResDesc = 'Good';
									self.eval.percentage = impPer;
									self.eval.desiredEvalResDesc = "90 to 100";
									self.eval.recommendations = ' ';
									self.recommendations1.a1 = 'Impact Evaluation : Should employ best practices to maintain current security evaluation percentage.';
								} else if (impPer <= 90 && impPer > 75) {
									self.eval.metricDesc = 'Security Budget Impact Evaluation';
									self.eval.evalResDesc = 'Medium';
									self.eval.percentage = impPer;
									self.eval.desiredEvalResDesc = "90 to 100";
									self.eval.recommendations = ' ';
									self.recommendations1.a1 = 'Impact Evaluation : Should enforce more standardized rules throughout organization for increase in security percentage.';
								} else if (impPer < 75) {
									self.eval.metricDesc = 'Security Budget Impact Evaluation';
									self.eval.evalResDesc = 'Bad';
									self.eval.percentage = impPer;
									self.eval.desiredEvalResDesc = "90 to 100";
									self.eval.recommendations = ' ';
									self.recommendations1.a1 = 'Impact Evaluation : Should consult a security analyst on priority and redesign organization specific security plan.';
								} else if (impPer >100) {
									self.eval.metricDesc = 'Security Budget Impact Evaluation';
									self.eval.evalResDesc = 'Cannot Determine. Please enter valid values in the above form.';
									self.eval.percentage = 0;
									self.eval.desiredEvalResDesc = "90 to 100";
									self.eval.recommendations = ' ';
									self.recommendations1.a1 = 'Impact Evaluation : No recommendation available.Please enter valid value in above form.';
								}

                                // Logic for rule implementation Metric 2 : Vulnerability Efficiency Evaluation

								if (vulnPer > 90 && vulnPer <= 100) {
									self.evaluation2.metricDesc = 'Vulnerability Efficiency Evaluation';
									self.evaluation2.evalResDesc = 'Good';
									self.evaluation2.percentage = vulnPer;
									self.evaluation2.desiredEvalResDesc = "90 to 100";
									self.evaluation2.recommendations = ' ';
									self.recommendations2.a1 = 'Vulnerability Evaluation : Should continuously monitor vulnerabilities to maintain current security percentage.';
								} else if (vulnPer <= 90 && vulnPer > 75) {
									self.evaluation2.metricDesc = 'Vulnerability Efficiency Evaluation';
									self.evaluation2.evalResDesc = 'Medium';
									self.evaluation2.percentage = vulnPer;
									self.evaluation2.desiredEvalResDesc = "90 to 100";
									self.evaluation2.recommendations = ' ';
									self.recommendations2.a1 = 'Vulnerability Evaluation : Should enforce strict regulations for mitigating vulnerabilities.';
								} else if (vulnPer < 75) {
									self.evaluation2.metricDesc = 'Vulnerability Efficiency Evaluation';
									self.evaluation2.evalResDesc = 'Bad';
									self.evaluation2.percentage = vulnPer;
									self.evaluation2.desiredEvalResDesc = "90 to 100";
									self.evaluation2.recommendations = ' ';
									self.recommendations2.a1 = 'Vulnerability Evaluation : Should consult a security analyst to built a secure infrastructure at organization level.';
								} else if (vulnPer > 100) {
									self.evaluation2.metricDesc = 'Vulnerability Efficiency Evaluation';
									self.evaluation2.evalResDesc = 'Cannot Determine. Please enter valid values in the above form.';
									self.evaluation2.percentage = 0;
									self.evaluation2.desiredEvalResDesc = "90 to 100";
									self.evaluation2.recommendations = ' ';
									self.recommendations2.a1 = 'Vulnerability Evaluation : No recommendation available.Please enter valid value in above form.';
								}
								console.log(self.user_inputs.c1);

                             /*Logic for rule implementation Metric 3 : Personnel Security Implementation Evaluation
                            Inferencing Rules logic is applied.
                            Based on user input selection, the next text field is displayed and the evaluation is carried out.

                            */
								switch (self.user_inputs.c1) {
								case 1:
									$scope.showTxtPanel1 = true;

									if (self.user_inputs.c2 == 0) {
										self.user_inputs.c2 = 1;
									}
									var per1 = (self.user_inputs.c3 / self.user_inputs.c2) * 100;

									if (per1 > 90 && per1 <= 100) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Good';
										self.evaluation3.percentage = per1;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should perform regular assessments to check for password encryption policies.';
									} else if (per1 <= 90 && per1 > 75) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Medium';
										self.evaluation3.percentage = per1;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should conduct informative sessions about importance of password encryption policies.';
									} else if (per1 < 75) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Bad';
										self.evaluation3.percentage = per1;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should consult a security analyst on priority and redesign organization specific password encryption policies.';
									} else if (per1 > 100) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Cannot Determine. Please enter valid values in the above form.';
										self.evaluation3.percentage = 0;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : No recommendation available.Please enter valid value in above form.';
									}
									break;
								case 2:
									$scope.showTxtPanel2 = true;

									if (self.user_inputs.c4 == 0) {
										self.user_inputs.c4 = 1;
									}
									var per2 = (self.user_inputs.c5 / self.user_inputs.c4) * 100;

									if (per2 > 90 && per2 <= 100) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Good';
										self.evaluation3.percentage = per2;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should employ best practices to assess the current technological advancements.';
									} else if (per2 <= 90 && per2 > 75) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Medium';
										self.evaluation3.percentage = per2;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should enforce more standardized rules throughout organization for regular software updates.';
									} else if (per2 < 75) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Bad';
										self.evaluation3.percentage = per2;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should consult a security analyst and design a infrastructure for software update policies.';
									} else if (per2 > 100) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Cannot Determine. Please enter valid values in the above form.';
										self.evaluation3.percentage = 0;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : No recommendation available.Please enter valid value in above form.';
									}
									break;
								case 3:
									self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
									self.evaluation3.evalResDesc = 'Bad';
									self.evaluation3.percentage = 0;
									self.evaluation3.desiredEvalResDesc = "90 to 100";
									self.evaluation3.recommendations = ' ';
									self.recommendations3.a1 = 'Personnel Security Evaluation : Should consult a security analyst on priority and design implementation specific policies for the organization.';

									break;
								case 4:
									$scope.showTxtPanel3 = true;

									if (self.user_inputs.c6 == 0) {
										self.user_inputs.c6 = 1;
									}
									var per3 = (self.user_inputs.c7 / self.user_inputs.c6) * 100;

									if (per3 > 90 && per3 <= 100) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Good';
										self.evaluation3.percentage = per3;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should maintain current standards by continuous assessments.';
									} else if (per3 <= 90 && per3 > 75) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Medium';
										self.evaluation3.percentage = per3;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should conduct training sessions for password and software update policies.';
									} else if (per3 < 75) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Bad';
										self.evaluation3.percentage = per3;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : Should consult a security analyst on priority and design the password and software update security framework.';
									} else if (per3 > 100) {
										self.evaluation3.metricDesc = 'Personnel Security Implementation Evaluation';
										self.evaluation3.evalResDesc = 'Cannot Determine. Please enter valid values in the above form.';
										self.evaluation3.percentage = 0;
										self.evaluation3.desiredEvalResDesc = "90 to 100";
										self.evaluation3.recommendations = ' ';
										self.recommendations3.a1 = 'Personnel Security Evaluation : No recommendation available.Please enter valid value in above form.';
									}
									break;
								}
								self.evaluations.push(angular.copy(self.eval));
								self.evaluations.push(angular
										.copy(self.evaluation2));
								self.evaluations.push(angular
										.copy(self.evaluation3));
								self.recommendations.push(angular
										.copy(self.recommendations1));
								self.recommendations.push(angular
										.copy(self.recommendations2));
								self.recommendations.push(angular
										.copy(self.recommendations3));

								console.log(self.evaluations);
							};
						} ]);