/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// ExtCardInfo
    /// </summary>
    [DataContract(Name = "ExtCardInfo")]
    public partial class ExtCardInfo : IEquatable<ExtCardInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ExtCardInfo" /> class.
        /// </summary>
        /// <param name="bankAccName">记账的外卡户名.</param>
        /// <param name="cardBank">记账的外卡开户行.</param>
        /// <param name="cardBranch">记账的外卡支行.</param>
        /// <param name="cardDeposit">记账的外卡联行号.</param>
        /// <param name="cardLocation">记账的外卡开户地址.</param>
        /// <param name="cardNo">记账的外卡卡号.</param>
        /// <param name="status">记账的外卡状态, A：正常状态;  其他：异常.</param>
        public ExtCardInfo(string bankAccName = default(string), string cardBank = default(string), string cardBranch = default(string), string cardDeposit = default(string), string cardLocation = default(string), string cardNo = default(string), string status = default(string))
        {
            this.BankAccName = bankAccName;
            this.CardBank = cardBank;
            this.CardBranch = cardBranch;
            this.CardDeposit = cardDeposit;
            this.CardLocation = cardLocation;
            this.CardNo = cardNo;
            this.Status = status;
        }

        /// <summary>
        /// 记账的外卡户名
        /// </summary>
        /// <value>记账的外卡户名</value>
        [DataMember(Name = "bank_acc_name", EmitDefaultValue = false)]
        public string BankAccName { get; set; }

        /// <summary>
        /// 记账的外卡开户行
        /// </summary>
        /// <value>记账的外卡开户行</value>
        [DataMember(Name = "card_bank", EmitDefaultValue = false)]
        public string CardBank { get; set; }

        /// <summary>
        /// 记账的外卡支行
        /// </summary>
        /// <value>记账的外卡支行</value>
        [DataMember(Name = "card_branch", EmitDefaultValue = false)]
        public string CardBranch { get; set; }

        /// <summary>
        /// 记账的外卡联行号
        /// </summary>
        /// <value>记账的外卡联行号</value>
        [DataMember(Name = "card_deposit", EmitDefaultValue = false)]
        public string CardDeposit { get; set; }

        /// <summary>
        /// 记账的外卡开户地址
        /// </summary>
        /// <value>记账的外卡开户地址</value>
        [DataMember(Name = "card_location", EmitDefaultValue = false)]
        public string CardLocation { get; set; }

        /// <summary>
        /// 记账的外卡卡号
        /// </summary>
        /// <value>记账的外卡卡号</value>
        [DataMember(Name = "card_no", EmitDefaultValue = false)]
        public string CardNo { get; set; }

        /// <summary>
        /// 记账的外卡状态, A：正常状态;  其他：异常
        /// </summary>
        /// <value>记账的外卡状态, A：正常状态;  其他：异常</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ExtCardInfo {\n");
            sb.Append("  BankAccName: ").Append(BankAccName).Append("\n");
            sb.Append("  CardBank: ").Append(CardBank).Append("\n");
            sb.Append("  CardBranch: ").Append(CardBranch).Append("\n");
            sb.Append("  CardDeposit: ").Append(CardDeposit).Append("\n");
            sb.Append("  CardLocation: ").Append(CardLocation).Append("\n");
            sb.Append("  CardNo: ").Append(CardNo).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as ExtCardInfo);
        }

        /// <summary>
        /// Returns true if ExtCardInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of ExtCardInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ExtCardInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BankAccName == input.BankAccName ||
                    (this.BankAccName != null &&
                    this.BankAccName.Equals(input.BankAccName))
                ) && 
                (
                    this.CardBank == input.CardBank ||
                    (this.CardBank != null &&
                    this.CardBank.Equals(input.CardBank))
                ) && 
                (
                    this.CardBranch == input.CardBranch ||
                    (this.CardBranch != null &&
                    this.CardBranch.Equals(input.CardBranch))
                ) && 
                (
                    this.CardDeposit == input.CardDeposit ||
                    (this.CardDeposit != null &&
                    this.CardDeposit.Equals(input.CardDeposit))
                ) && 
                (
                    this.CardLocation == input.CardLocation ||
                    (this.CardLocation != null &&
                    this.CardLocation.Equals(input.CardLocation))
                ) && 
                (
                    this.CardNo == input.CardNo ||
                    (this.CardNo != null &&
                    this.CardNo.Equals(input.CardNo))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.BankAccName != null)
                {
                    hashCode = (hashCode * 59) + this.BankAccName.GetHashCode();
                }
                if (this.CardBank != null)
                {
                    hashCode = (hashCode * 59) + this.CardBank.GetHashCode();
                }
                if (this.CardBranch != null)
                {
                    hashCode = (hashCode * 59) + this.CardBranch.GetHashCode();
                }
                if (this.CardDeposit != null)
                {
                    hashCode = (hashCode * 59) + this.CardDeposit.GetHashCode();
                }
                if (this.CardLocation != null)
                {
                    hashCode = (hashCode * 59) + this.CardLocation.GetHashCode();
                }
                if (this.CardNo != null)
                {
                    hashCode = (hashCode * 59) + this.CardNo.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
