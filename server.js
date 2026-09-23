import app from './src/app.js';
import connectDB from './config/database.js';

connectDB();

app.listen(3000,()=>{
    
    console.log("app listen at 3000");
})