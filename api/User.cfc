
component restpath="/users"  rest="true" {
    variables.dataSource = "cf_learning";

    remote struct function signup() httpmethod="POST" restpath="sign-up" {
        var reqeustData = getHTTPRequestData();
        var newUser = deserializeJSON(reqeustData.content);
        
        var hashedPassword = generateArgon2Hash(newUser["password"]);

        newUser["password"] = hashedPassword;

        var sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        var result = queryExecute(sql, [newUser["username"], newUser["password"]], {dataSource = variables.dataSource})
        
        cfheader(statusCode="201", statusText="Created");
        return {"message": "Sign-up successful"};
    }
    
    remote any function signin() httpmethod="POST" restpath="sign-in" {
        var requestData = getHTTPRequestData();
        
        var user = deserializeJSON(requestData.content);
        
        var sql = "SELECT * FROM users WHERE username = ?";
        var result = queryExecute(sql, [user["username"]], {dataSource = variables.dataSource})
        
        if (result.recordCount == 0){
            cfheader(statusCode="404", statusText="Not Found");
            return {"message": "User with given username not found"};
        }

        if (!argon2CheckHash(user["password"], result.password[1])){
            cfheader(statusCode="401", statusText="Unauthorized");
            return {"message": "Wrong password"};
        }

        
        var jwtClient = new lib.JsonWebTokens().createClient( "HS256", "SUPER SECRET STUFF LOL" );
        var jwtToken = jwtClient.encode( {"username": user["username"]} );
        
        cfheader(statusCode="200", statusText="OK");
        return {"access_token": jwtToken};

    }


}
