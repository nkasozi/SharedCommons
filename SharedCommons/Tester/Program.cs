using System;
using System.Collections.Generic;
using System.Linq;
using System.Messaging;
using System.Text;
using System.Threading.Tasks;

namespace Tester
{
    class Program
    {
        public static void Main(string[] args)
        {
            string QueuePath = @".\private$\TestQueue"; ;
            CommonResult result = new CommonResult();
            result.StatusCode = SharedCommonsGlobals.SUCCESS_STATUS_CODE;
            result.StatusDesc = SharedCommonsGlobals.SUCCESS_STATUS_TEXT;
            CommonResult insertResult = SharedCommons.InsertIntoMSMQ(QueuePath, result);
            Message message = SharedCommons.PeekCopyOfTopItemFromMSMQ(QueuePath,typeof(CommonResult));
            
            result = message.Body as CommonResult;
            bool isValid = SharedCommons.IsValidUgPhoneNumber("0785975800");
        }
    }
}
