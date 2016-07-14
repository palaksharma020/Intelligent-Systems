'use strict';

App
		.controller(
				'SecurityController',
				[
						'$http',
						'$scope',
						function($http, $scope, SecurityService) {
							$http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
							var self = this;
							self.user_inputs = {
								a1 : '',
								a2 : '',
								b1 : '',
								b2 : '',
								c1 : '',
								c2 : '',
								c3 : '',
								c4 : '',
								c5 : '',
								c6 : '',
								d1 : '',
								d2 : '',
								e1 : '',
								e2 : ''
							};

							self.evaluations = [];
							self.recommendations = [];
							
							self.sendPost = function() {
								$http({
									url : 'SecurityServlet',
									method : "POST",
									data : {
										'name' : 'abc',
										'a1' : self.user_inputs.a1,
										'a2' : self.user_inputs.a2,
										'b1' : self.user_inputs.b1,
										'b2' : self.user_inputs.b2,
										'c1' : self.user_inputs.c1,
										'c2' : self.user_inputs.c2,
										'c3' : self.user_inputs.c3,
										'c4' : self.user_inputs.c4,
										'c5' : self.user_inputs.c5,
										'c6' : self.user_inputs.c6,
										'd1' : self.user_inputs.d1,
										'd2' : self.user_inputs.d2,
										'e1' : self.user_inputs.e1,
										'e2' : self.user_inputs.e2,
									}
								})
										.then(
												function(response) {
													$scope.showPanel = true;
													console.log(response.data.evaluationList);
													console.log(response.data.recommendationList);
													console.log(response.data);
													self.evaluations = response.data.evaluationList;
													self.recommendations = response.data.recommendationList;
													console
															.log(self.evaluations);
												}, function(response) {
													// fail case
													console.log(response);
												});

							};
						} ]);