const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");


//signup route handler
exports.signup = async (req,res) => {
    try{
        //get data
        const {name, email, password,  role} = req.body;

        //check if user already exist
        const existingUser = await User.findOne({email});

        if(existingUser){
            return res.status(400).json({
                success: false,
                message: 'User already Exist',
            });
        }
        //secure password
        let hashPassword;
        try{
            hashPassword = await bcrypt.hash(password, 10);
        }
        catch(err){
            return res.status(500).json({
                success: false,
                message: 'Error in hashing Password',
            });
        }

        //create entry for user

        const user = await User.create({
            name,email,password:hashedPassword,role
        })

        return res.status(200).json({
            success: true,
            message: 'User created Successsfully',
        });

    }
    catch(error){
        console.error(error);
        return res.status(500).json({
            success: false,
            message: 'User cannot be registed please try again later',
        });
        
    }
};

//https://www.npmjs.com/package/bcrypt

// Login
exports.login = async (req,res) => {
    try
    {
        const {email,password} = req.body;
        if(!email || !password)
        {
            return res.status(400).json({
                success:false,
                message : "Please fill all the details carefully",
            })
        }

        // check for register user 
        let user = await User.findOne({email});
        if(!user)
        {
            return res.status(401).json({
                success : false,
                message : "User does not exist",
            });
        }

        // Verify password & generate a JWT token

        const payload = { //extracting data from user
            email : user.email,
            id : user._id,
            role : user.role,
        };


        //Token is genarete during login
        if(await bcrypt.compare(password,user.password)){
            // password match

            //creating token
            let token = jwt.sign(payload,process.env.JWT_SECRET,{
                expiresIn : "2h",
            });
            //payload,secret,option
            user = user.toObject();
            user.token = token;
            user.password = undefined;

            const options = {
                expires : new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly : true, //not accessable in client side
            }

            //By this method server will sent cookies to the client in res
            // res.cookie("token",token,options).status(200).json({
            //     success : true,
            //     token,
            //     user,
            //     message:"User logged in successfully"
            // });

            res.status(200).json({
                success : true,
                token,
                user,
                message:"User loged in successfully"
            });
        }
        else {
            // password not match
            return res.status(403).json({
                success : false,
                message : "Password does not match",
            })
        }
    }
    catch(err){
        console.error(err);
        return res.status(500).json({
            success : false,
            message : "Login false" 
        })
    }
}