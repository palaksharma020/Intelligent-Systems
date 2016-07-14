'use strict';
 
App.factory('SecurityService', ['$http', '$q', function($http, $q){
			
    return {
    	
    	
            fetchEvaluationReport: function() {
                    return $http.get('http://localhost:8080/SecurityEvaluationWebApp/service/security/eval')
                            .then(
                                    function(response){
                                        return response.data;
                                    }, 
                                    function(errResponse){
                                        console.error('Error while fetching evaluation report');
                                        return $q.reject(errResponse);
                                    }
                            );
            },
             
            fetchRecommendationReport: function() {
                return $http.get('http://localhost:8080/SecurityEvaluationWebApp/service/security/rec')
                        .then(
                                function(response){
                                    return response.data;
                                }, 
                                function(errResponse){
                                    console.error('Error while fetching recommendation report');
                                    return $q.reject(errResponse);
                                }
                        );
            },
            
            postUserInputs: function(user){
            	var req = {
           			 method: 'POST',
           			 url: 'http://localhost:8080/SecurityEvaluationWebApp/userinput',
           			 headers: {
           			   'Content-Type': 'application/json'
           			 },
           			 data: user
           			};
                    return $http.post(req)
                            .then(
                                    function(response){
                                    	console.log("Hiiiii");
                                        return response.data;
                                    }, 
                                    function(errResponse){
                                        console.error('Error while posting user input.');
                                        return $q.reject(errResponse);
                                    }
                            );
            }
    };
}]);