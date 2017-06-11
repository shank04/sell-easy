var express= require('express');
var mongoose = require('mongoose');
var app = express();
var bodyParser = require('body-parser');
var async = require('async');
var expressValidator = require('express-validator');
var passport = require('passport');
var flash    = require('connect-flash');
var session      = require('express-session');
var bcrypt   = require('bcrypt-nodejs');
var LocalStrategy   = require('passport-local').Strategy;
var cookieParser = require('cookie-parser');
var path = require('path');




app.set('view engine', 'pug');
app.set('views','./views');
app.use(express.static('public'))
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(expressValidator()); 
app.use(cookieParser());
app.use(session({ secret: 'SessionID' }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());



mongoose.Promise = global.Promise;

mongoose.connect('mongodb://localhost/new9_db');

var db = mongoose.connection;
db.on('error',console.error.bind(console,'connection error'));


var itemSchema=mongoose.Schema({
	'category' : {type:mongoose.Schema.Types.ObjectId, ref:'ItemsCategory', required:[true,"{PATH} is required"]},
	'brand' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'price' : {type:String , required:[true,"{PATH} is required"] , trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'} 
				// validate : {
				// 	validator : function(v){
				// 		var i = parseInt(v);
				// 		return isInteger(i);
						

				// 	},
				// 	message : "{VALUE} is not a valid price"
				// }
			
});

itemSchema.virtual('url').get(function(){
	return '/items/'+this._id;
});

var itemsCategorySchema=mongoose.Schema({
	'name' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'} 

});

itemsCategorySchema.virtual('url').get(function(){
	return '/itemsCategory/'+this._id;
});


var  customerSchema = mongoose.Schema({
	'name' : {type:String,required:[true,"{PATH} is required"],trim:true},
	'address' : {
		'houseNo' : {type:Number, required:[true,"{PATH} is required"],trim:true},
		'street' : {type:Number, required:[true,"{PATH} is required"],trim:true},
		'district' : {type:String, required:[true,"{PATH} is required"],trim:true},
		'PIN' : {type:Number, required:[true,"{PATH} is required"],trim:true}
	},
	'phone' : {type:String, required:[true,"{PATH} is required"],trim:true,
			validate : {
					validator : function(s){
						
						return s.match(/\d{10}/);
						

					},
					message : "{VALUE} is not a valid phone number"
				}
			},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'} 

	// 'credit' : {type:Number, required:[true,"{PATH} is required"],trim:true, default : 0, max : [1000, "Credit limit exceeded"]}
});

customerSchema.virtual('url').get(function(){
	return '/customers/'+this._id;
});

var billSchema = mongoose.Schema({
	'category' : [{type : mongoose.Schema.Types.ObjectId, ref:'ItemsCategory', required:[true,"{PATH} is required"]}],
	'customer' : {type : mongoose.Schema.Types.ObjectId, ref:'Customers', required:[true,"{PATH} is required"]},
	'items' : [{type : mongoose.Schema.Types.ObjectId, ref:'Items', required:[true,"{PATH} is required"]}],
	'cost' : [{type: Number}],
	'quantity' : [{type : Number}],
	'amount' : {type : Number, default : 0},
	'generated_at' : {type : Date, default : Date.now},
	'user'  : {type:mongoose.Schema.Types.ObjectId, ref:'User'} 

});

billSchema.virtual('url').get(function(){
	return '/viewBill/'+this._id;
});



var userSchema = mongoose.Schema({
		shopname	 : {type:String, required:[true,"{PATH} is required"],trim:true},
		username     : {type:String, required:[true,"{PATH} is required"],trim:true},
		email        : {type:String, required:[true,"{PATH} is required"],trim:true},
        password     : {type:String, required:[true,"{PATH} is required"],trim:true},
        confirmpassword     : {type:String},

});

userSchema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};


userSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};


var Items = mongoose.model('Items',itemSchema);
var ItemsCategory = mongoose.model('ItemsCategory',itemsCategorySchema);
var Customers = mongoose.model('Customers',customerSchema);
var Bill = mongoose.model('Bill', billSchema);
var User = mongoose.model('User', userSchema);


passport.serializeUser(function(user, done) {
        done(null, user.id);
});

passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
});

passport.use('local-signup', new LocalStrategy({
        
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true
    },
    function(req, email, password, done) {
    	username=req.body.username;
    	shopname=req.body.shopname;
    	confirmpassword=req.body.confirmpassword;

        process.nextTick(function() {
        	if(password != confirmpassword) {
                return done(null, false, req.flash('signupMessage', 'Passwords do not match.'));
            }

        User.findOne({ 'username' :  username }, function(err, user) {
            if (err)
                return done(err);

            if (user) {
                return done(null, false, req.flash('signupMessage', 'That username is already taken.'));
            } else {

                var newUser = new User();

                // set the user's local credentials
                newUser.shopname = shopname;
                newUser.username = username;
                newUser.email    = email;
                newUser.password = newUser.generateHash(password);

                // save the user
                newUser.save(function(err) {
                    if (err){
                    	console.log(err);
                    }
                       
                    return done(null, newUser);
                });
            }

        });    

        });

    }));




passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'username',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, username, password, done) { // callback with email and password from our form

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'username' :  username }, function(err, user) {
            // if there are any errors, return the error before anything else
            if (err)
                return done(err);

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            return done(null, user);
        });

    }));



app.get('/', function(req, res){
	
	if (req.isAuthenticated()){
		user=req.user;
		console.log(user);
		Bill
		.find({ 'user':user._id })
		.populate('customer')
		.exec(function (err, bills) {
  		if (err) throw err;
			res.render("index.pug", {user:user, bills : bills});
  	});
		
	}
	else{
		res.render("unindex.pug");

	}

	});


app.get('/viewCategory', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		async.parallel({
		categs : function(callback){
			ItemsCategory.find({'user':user._id}, callback);
		}
	},function(err, results){
		if(err) return console.error(err);
		res.render('viewCategory.pug', {categs : results.categs, user : user});

	});

	}
	else{
		res.send("You need to be logged in to view this");
	}
});

app.get('/viewBrands/:id', function(req,res){
	if(req.isAuthenticated()){
		c=req.params.id;
		user=req.user;
		async.parallel({
		items : function(callback){
			Items.find({'user':user._id, 'category':c}, callback);
		},
		categs : function(callback){
			ItemsCategory.findById(c, callback);
		}
	},function(err, results){
		if(err) return console.error(err);
		res.render('viewBrands.pug', {items : results.items, user : user, categ : results.categs});

	});


	}
	else{
		res.send("You need to be logged in to view this");
	}
});

app.get('/viewCustomers', function(req,res){
	if(req.isAuthenticated()){
		user=req.user;
		async.parallel({
		customers : function(callback){
			Customers.find({'user':user._id}, callback);
		}
	},function(err, results){
		if(err) return console.error(err);
		res.render('viewCustomer.pug', {customers : results.customers, user : user});

	});

	}
	else{
		res.send("You need to be logged in to view this");
	}
});

app.get('/customer/:id', function(req,res){
	if(req.isAuthenticated()){
		c=req.params.id;
		user=req.user;
		async.parallel({
		
		customer : function(callback){
			Customers.findById(c, callback);
		}
	},function(err, results){
		if(err) return console.error(err);
		res.render('customer.pug', {customer : results.customer, user : user});

	});


	}
	else{
		res.send("You need to be logged in to view this");
	}
});

app.get('/viewBill/:id', function(req,res){
	if(req.isAuthenticated()){
		c=req.params.id;
		user=req.user;
		Bill
		.findById(c)
		.populate('customer category items')
		.exec(function (err, bill) {
  		if (err) throw err;
			res.render("viewBill.pug", {user:user, bill : bill});
  	});

	}
	else{
		res.send("You need to be logged in to view this");
	}
});

app.get('/addCategory', function(req, res){
	if(req.isAuthenticated()){
		user=req.user;

	res.render('addCategory',{user:user});
}
else{
		res.send("You need to be logged in to view this");
	}
});

app.post('/addCategory', function(req, res){
		user=req.user;

	var cc = new ItemsCategory({
		name : req.body.name,
		user : req.user._id
	});

	cc.save(function(err){
		if(err){
			console.log(err);
			res.render('addCategory', {error : err, category : cc, user : user});
		}
		else{
			console.log('New category added');
			res.redirect('/');
		}
	});
});

app.get('/addItem', function(req, res){
	if(req.isAuthenticated()){
		user=req.user;

	async.parallel({
		categs : function(callback){
			ItemsCategory.find({'user' : user._id}, callback);
		}
	},function(err, results){
		if(err) return console.error(err);
		res.render('addItem', {categs : results.categs, user : user});

	});
	}
	else{
		res.send("You need to be logged in to view this");
	}
});

app.post('/addItem',function(req,res){
		user=req.user;
		
	 	var i=new Items({
			category : req.body.category,
	 		brand : req.body.brand,
			price : req.body.price,
			user : req.user._id

			
		});
				
		i.save(function(err){
			if(err){
				async.parallel({
					categs : function(callback){
						ItemsCategory.find({'user' : user._id}, callback);
					}

					},function(errr, results){
						if(errr) return console.error(errr);
						// console.log(err);
						res.render('addItem', {categs : results.categs, error : err, item :i, user: user});

	});			}
			else{
				console.log("New Item Added");
				res.redirect('/');
			}
		});
	
});


app.get('/addCustomer', function(req, res){
	if(req.isAuthenticated()){
		user=req.user;

	res.render('addCustomer', {user : user});
}
else{
		res.send("You need to be logged in to view this");
	}
});

app.post('/addCustomer', function(req, res){
	user=req.user;
	var c = new Customers({
		name : req.body.name,
		address : {
			houseNo : req.body.houseNo,
			street : req.body.street,
			district : req.body.district,
			PIN : req.body.PIN,
		},
		phone : req.body.phone,
		user : req.user._id

	
	});
	console.log(c);
	c.save(function(err){
		if(err){
			console.log(err);
			res.render('addCustomer', {error : err, customer : c, user: user});
		}
		else{
			console.log('New customer added');
			res.redirect('/');
		}
	});
	
});


app.get('/billing', function(req, res){
	if(req.isAuthenticated()){
		user=req.user;

	async.parallel({
		customers : function(callback){
			Customers.find({'user' : user._id}, callback);
		},
		items : function(callback){
			Items.find({'user' : user._id}, callback);
		},
		categs : function(callback){
			ItemsCategory.find({'user' : user._id}, callback);
		}
	}, function(err, results){
		if(err) return console.error(err);
		res.render('generateBill.pug', {customers : results.customers, items : results.items, categs : results.categs, user: user});
	}
	);
}
else{
		res.send("You need to be logged in to view this");
	}
});

app.post('/billing', function(req, res){
	user: req.user;
	var bill = new Bill({
		category : req.body.category,
		customer : req.body.customer,
		items : req.body.items,
		quantity : req.body.quantity,
		cost : req.body.cost,
		amount : req.body.amount,
		generated_at : req.body.timestamp,
		user : req.user._id

	});

	bill.save(function(err){
		if (err){
			console.log(err);
			async.parallel({
		customers : function(callback){
			Customers.find({'user' : user._id}, callback);
		},
		items : function(callback){
			Items.find({'user' : user._id}, callback);
		},
		categs : function(callback){
			ItemsCategory.find({'user' : user._id}, callback);
		}
	}, function(errr, results){
		if(errr) return console.error(errr);
		res.render('generateBill.pug', {customers : results.customers, items : results.items, error : err, bill : bill, categs : results.categs, user:user});
	}
	);

	}
	else{
		console.log("Bill Generated");
		res.redirect('/');
	}
	});

});


app.get('/login', function(req,res){
    res.render('login.pug', { message: req.flash('loginMessage') }); 
});

app.post('/login', passport.authenticate('local-login', {
    successRedirect : '/', // redirect to the secure profile section
    failureRedirect : '/login', // redirect back to the signup page if there is an error
    failureFlash : true // allow flash messages
}));


app.get('/signup', function(req,res){
    res.render('signup.pug', { message: req.flash('signupMessage') });
});

app.post('/signup', passport.authenticate('local-signup', {
    successRedirect : '/', // redirect to the secure profile section
    failureRedirect : '/signup', // redirect back to the signup page if there is an error
    failureFlash : true // allow flash messages
}));


app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });

app.get('*', function(req,res){
	res.status(404).send(`Oops! Error 404, Page not found. Go to <a href="/">home</a> page`);
});


function isLoggedIn(req, res, next) {
 
    if (req.isAuthenticated())
        return next();

    res.redirect('/');
}


app.listen(3000, function(){
	console.log('Connected');
});


