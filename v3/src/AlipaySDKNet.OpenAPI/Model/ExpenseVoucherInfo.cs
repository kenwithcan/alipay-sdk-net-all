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
    /// ExpenseVoucherInfo
    /// </summary>
    [DataContract(Name = "ExpenseVoucherInfo")]
    public partial class ExpenseVoucherInfo : IEquatable<ExpenseVoucherInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ExpenseVoucherInfo" /> class.
        /// </summary>
        /// <param name="accountId">企业支付宝用户id(对应凭证ownerid).</param>
        /// <param name="consumptionDate">消费时间.</param>
        /// <param name="employeeId">员工ID.</param>
        /// <param name="employeeOpenId">员工ID.</param>
        /// <param name="extension">扩展预留.</param>
        /// <param name="gmtCreate">数据创建时间.</param>
        /// <param name="gmtModified">数据更新时间.</param>
        /// <param name="industry">行业属性值（从支付宝主账单复制）.</param>
        /// <param name="isOffSet">是否冲抵凭证：0 否（蓝票）；1 是(如:红票).</param>
        /// <param name="medium">凭证介质：纸or电子(PAPER,ELECTRON).</param>
        /// <param name="outerSourceId">外部唯一ID（和凭证类型有关，如果发票类型为发票号码+发票编码，如果是账单，则为账单号）.</param>
        /// <param name="parentType">凭证父类型（INVOICE-发票，TRAVEL-出行凭证，HTL_ORDER-酒店水单，CONSUME-账单，财政票夹）.</param>
        /// <param name="voucherAmount">交易金额（元）.</param>
        /// <param name="voucherDate">凭证创建时间.</param>
        /// <param name="voucherId">凭证ID.</param>
        /// <param name="voucherNo">一类凭证，唯一号码，有必须传，没有可不传。 发票、账单必须有 如部分餐饮小票，没有唯一号.</param>
        /// <param name="voucherState">凭证状态(0-无效，1 有效).</param>
        /// <param name="voucherType">凭证类型 （FINANCIAL_BILLS-财政电子票 MEDICAL_INVOICE-医疗票据 DONATION_INVOICE-公益捐赠电子票据 SETTLEMENT_INVOICE-往来结算票据 DUES_INVOICE-社会团体会费收据 INVOICE-增值税票 PLAIN-增值税电子普通发票 SPECIAL-增值税专用发票 PLAIN_INVOICE-增值税普通发票 PAPER_INVOICE-增值税普通发票(卷式) CONSUME-账单 ALIPAY_CONSUME-支付宝账单 TRAVEL-出行凭证 TAXI-出租车票 BUS_TICKET-汽车票 TRAIN-火车票 TOLL-过路费 BOARD_PASS-登机牌 HTL_ORDER-酒店水单 MEMO-酒店水单 OTHERS-杂票 FIXED-定额发票 LIST-小票 COMMON_INVOICE-通用发票）.</param>
        public ExpenseVoucherInfo(string accountId = default(string), string consumptionDate = default(string), string employeeId = default(string), string employeeOpenId = default(string), string extension = default(string), string gmtCreate = default(string), string gmtModified = default(string), string industry = default(string), string isOffSet = default(string), string medium = default(string), string outerSourceId = default(string), string parentType = default(string), string voucherAmount = default(string), string voucherDate = default(string), string voucherId = default(string), string voucherNo = default(string), string voucherState = default(string), string voucherType = default(string))
        {
            this.AccountId = accountId;
            this.ConsumptionDate = consumptionDate;
            this.EmployeeId = employeeId;
            this.EmployeeOpenId = employeeOpenId;
            this.Extension = extension;
            this.GmtCreate = gmtCreate;
            this.GmtModified = gmtModified;
            this.Industry = industry;
            this.IsOffSet = isOffSet;
            this.Medium = medium;
            this.OuterSourceId = outerSourceId;
            this.ParentType = parentType;
            this.VoucherAmount = voucherAmount;
            this.VoucherDate = voucherDate;
            this.VoucherId = voucherId;
            this.VoucherNo = voucherNo;
            this.VoucherState = voucherState;
            this.VoucherType = voucherType;
        }

        /// <summary>
        /// 企业支付宝用户id(对应凭证ownerid)
        /// </summary>
        /// <value>企业支付宝用户id(对应凭证ownerid)</value>
        [DataMember(Name = "account_id", EmitDefaultValue = false)]
        public string AccountId { get; set; }

        /// <summary>
        /// 消费时间
        /// </summary>
        /// <value>消费时间</value>
        [DataMember(Name = "consumption_date", EmitDefaultValue = false)]
        public string ConsumptionDate { get; set; }

        /// <summary>
        /// 员工ID
        /// </summary>
        /// <value>员工ID</value>
        [DataMember(Name = "employee_id", EmitDefaultValue = false)]
        public string EmployeeId { get; set; }

        /// <summary>
        /// 员工ID
        /// </summary>
        /// <value>员工ID</value>
        [DataMember(Name = "employee_open_id", EmitDefaultValue = false)]
        public string EmployeeOpenId { get; set; }

        /// <summary>
        /// 扩展预留
        /// </summary>
        /// <value>扩展预留</value>
        [DataMember(Name = "extension", EmitDefaultValue = false)]
        public string Extension { get; set; }

        /// <summary>
        /// 数据创建时间
        /// </summary>
        /// <value>数据创建时间</value>
        [DataMember(Name = "gmt_create", EmitDefaultValue = false)]
        public string GmtCreate { get; set; }

        /// <summary>
        /// 数据更新时间
        /// </summary>
        /// <value>数据更新时间</value>
        [DataMember(Name = "gmt_modified", EmitDefaultValue = false)]
        public string GmtModified { get; set; }

        /// <summary>
        /// 行业属性值（从支付宝主账单复制）
        /// </summary>
        /// <value>行业属性值（从支付宝主账单复制）</value>
        [DataMember(Name = "industry", EmitDefaultValue = false)]
        public string Industry { get; set; }

        /// <summary>
        /// 是否冲抵凭证：0 否（蓝票）；1 是(如:红票)
        /// </summary>
        /// <value>是否冲抵凭证：0 否（蓝票）；1 是(如:红票)</value>
        [DataMember(Name = "is_off_set", EmitDefaultValue = false)]
        public string IsOffSet { get; set; }

        /// <summary>
        /// 凭证介质：纸or电子(PAPER,ELECTRON)
        /// </summary>
        /// <value>凭证介质：纸or电子(PAPER,ELECTRON)</value>
        [DataMember(Name = "medium", EmitDefaultValue = false)]
        public string Medium { get; set; }

        /// <summary>
        /// 外部唯一ID（和凭证类型有关，如果发票类型为发票号码+发票编码，如果是账单，则为账单号）
        /// </summary>
        /// <value>外部唯一ID（和凭证类型有关，如果发票类型为发票号码+发票编码，如果是账单，则为账单号）</value>
        [DataMember(Name = "outer_source_id", EmitDefaultValue = false)]
        public string OuterSourceId { get; set; }

        /// <summary>
        /// 凭证父类型（INVOICE-发票，TRAVEL-出行凭证，HTL_ORDER-酒店水单，CONSUME-账单，财政票夹）
        /// </summary>
        /// <value>凭证父类型（INVOICE-发票，TRAVEL-出行凭证，HTL_ORDER-酒店水单，CONSUME-账单，财政票夹）</value>
        [DataMember(Name = "parent_type", EmitDefaultValue = false)]
        public string ParentType { get; set; }

        /// <summary>
        /// 交易金额（元）
        /// </summary>
        /// <value>交易金额（元）</value>
        [DataMember(Name = "voucher_amount", EmitDefaultValue = false)]
        public string VoucherAmount { get; set; }

        /// <summary>
        /// 凭证创建时间
        /// </summary>
        /// <value>凭证创建时间</value>
        [DataMember(Name = "voucher_date", EmitDefaultValue = false)]
        public string VoucherDate { get; set; }

        /// <summary>
        /// 凭证ID
        /// </summary>
        /// <value>凭证ID</value>
        [DataMember(Name = "voucher_id", EmitDefaultValue = false)]
        public string VoucherId { get; set; }

        /// <summary>
        /// 一类凭证，唯一号码，有必须传，没有可不传。 发票、账单必须有 如部分餐饮小票，没有唯一号
        /// </summary>
        /// <value>一类凭证，唯一号码，有必须传，没有可不传。 发票、账单必须有 如部分餐饮小票，没有唯一号</value>
        [DataMember(Name = "voucher_no", EmitDefaultValue = false)]
        public string VoucherNo { get; set; }

        /// <summary>
        /// 凭证状态(0-无效，1 有效)
        /// </summary>
        /// <value>凭证状态(0-无效，1 有效)</value>
        [DataMember(Name = "voucher_state", EmitDefaultValue = false)]
        public string VoucherState { get; set; }

        /// <summary>
        /// 凭证类型 （FINANCIAL_BILLS-财政电子票 MEDICAL_INVOICE-医疗票据 DONATION_INVOICE-公益捐赠电子票据 SETTLEMENT_INVOICE-往来结算票据 DUES_INVOICE-社会团体会费收据 INVOICE-增值税票 PLAIN-增值税电子普通发票 SPECIAL-增值税专用发票 PLAIN_INVOICE-增值税普通发票 PAPER_INVOICE-增值税普通发票(卷式) CONSUME-账单 ALIPAY_CONSUME-支付宝账单 TRAVEL-出行凭证 TAXI-出租车票 BUS_TICKET-汽车票 TRAIN-火车票 TOLL-过路费 BOARD_PASS-登机牌 HTL_ORDER-酒店水单 MEMO-酒店水单 OTHERS-杂票 FIXED-定额发票 LIST-小票 COMMON_INVOICE-通用发票）
        /// </summary>
        /// <value>凭证类型 （FINANCIAL_BILLS-财政电子票 MEDICAL_INVOICE-医疗票据 DONATION_INVOICE-公益捐赠电子票据 SETTLEMENT_INVOICE-往来结算票据 DUES_INVOICE-社会团体会费收据 INVOICE-增值税票 PLAIN-增值税电子普通发票 SPECIAL-增值税专用发票 PLAIN_INVOICE-增值税普通发票 PAPER_INVOICE-增值税普通发票(卷式) CONSUME-账单 ALIPAY_CONSUME-支付宝账单 TRAVEL-出行凭证 TAXI-出租车票 BUS_TICKET-汽车票 TRAIN-火车票 TOLL-过路费 BOARD_PASS-登机牌 HTL_ORDER-酒店水单 MEMO-酒店水单 OTHERS-杂票 FIXED-定额发票 LIST-小票 COMMON_INVOICE-通用发票）</value>
        [DataMember(Name = "voucher_type", EmitDefaultValue = false)]
        public string VoucherType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ExpenseVoucherInfo {\n");
            sb.Append("  AccountId: ").Append(AccountId).Append("\n");
            sb.Append("  ConsumptionDate: ").Append(ConsumptionDate).Append("\n");
            sb.Append("  EmployeeId: ").Append(EmployeeId).Append("\n");
            sb.Append("  EmployeeOpenId: ").Append(EmployeeOpenId).Append("\n");
            sb.Append("  Extension: ").Append(Extension).Append("\n");
            sb.Append("  GmtCreate: ").Append(GmtCreate).Append("\n");
            sb.Append("  GmtModified: ").Append(GmtModified).Append("\n");
            sb.Append("  Industry: ").Append(Industry).Append("\n");
            sb.Append("  IsOffSet: ").Append(IsOffSet).Append("\n");
            sb.Append("  Medium: ").Append(Medium).Append("\n");
            sb.Append("  OuterSourceId: ").Append(OuterSourceId).Append("\n");
            sb.Append("  ParentType: ").Append(ParentType).Append("\n");
            sb.Append("  VoucherAmount: ").Append(VoucherAmount).Append("\n");
            sb.Append("  VoucherDate: ").Append(VoucherDate).Append("\n");
            sb.Append("  VoucherId: ").Append(VoucherId).Append("\n");
            sb.Append("  VoucherNo: ").Append(VoucherNo).Append("\n");
            sb.Append("  VoucherState: ").Append(VoucherState).Append("\n");
            sb.Append("  VoucherType: ").Append(VoucherType).Append("\n");
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
            return this.Equals(input as ExpenseVoucherInfo);
        }

        /// <summary>
        /// Returns true if ExpenseVoucherInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of ExpenseVoucherInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ExpenseVoucherInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AccountId == input.AccountId ||
                    (this.AccountId != null &&
                    this.AccountId.Equals(input.AccountId))
                ) && 
                (
                    this.ConsumptionDate == input.ConsumptionDate ||
                    (this.ConsumptionDate != null &&
                    this.ConsumptionDate.Equals(input.ConsumptionDate))
                ) && 
                (
                    this.EmployeeId == input.EmployeeId ||
                    (this.EmployeeId != null &&
                    this.EmployeeId.Equals(input.EmployeeId))
                ) && 
                (
                    this.EmployeeOpenId == input.EmployeeOpenId ||
                    (this.EmployeeOpenId != null &&
                    this.EmployeeOpenId.Equals(input.EmployeeOpenId))
                ) && 
                (
                    this.Extension == input.Extension ||
                    (this.Extension != null &&
                    this.Extension.Equals(input.Extension))
                ) && 
                (
                    this.GmtCreate == input.GmtCreate ||
                    (this.GmtCreate != null &&
                    this.GmtCreate.Equals(input.GmtCreate))
                ) && 
                (
                    this.GmtModified == input.GmtModified ||
                    (this.GmtModified != null &&
                    this.GmtModified.Equals(input.GmtModified))
                ) && 
                (
                    this.Industry == input.Industry ||
                    (this.Industry != null &&
                    this.Industry.Equals(input.Industry))
                ) && 
                (
                    this.IsOffSet == input.IsOffSet ||
                    (this.IsOffSet != null &&
                    this.IsOffSet.Equals(input.IsOffSet))
                ) && 
                (
                    this.Medium == input.Medium ||
                    (this.Medium != null &&
                    this.Medium.Equals(input.Medium))
                ) && 
                (
                    this.OuterSourceId == input.OuterSourceId ||
                    (this.OuterSourceId != null &&
                    this.OuterSourceId.Equals(input.OuterSourceId))
                ) && 
                (
                    this.ParentType == input.ParentType ||
                    (this.ParentType != null &&
                    this.ParentType.Equals(input.ParentType))
                ) && 
                (
                    this.VoucherAmount == input.VoucherAmount ||
                    (this.VoucherAmount != null &&
                    this.VoucherAmount.Equals(input.VoucherAmount))
                ) && 
                (
                    this.VoucherDate == input.VoucherDate ||
                    (this.VoucherDate != null &&
                    this.VoucherDate.Equals(input.VoucherDate))
                ) && 
                (
                    this.VoucherId == input.VoucherId ||
                    (this.VoucherId != null &&
                    this.VoucherId.Equals(input.VoucherId))
                ) && 
                (
                    this.VoucherNo == input.VoucherNo ||
                    (this.VoucherNo != null &&
                    this.VoucherNo.Equals(input.VoucherNo))
                ) && 
                (
                    this.VoucherState == input.VoucherState ||
                    (this.VoucherState != null &&
                    this.VoucherState.Equals(input.VoucherState))
                ) && 
                (
                    this.VoucherType == input.VoucherType ||
                    (this.VoucherType != null &&
                    this.VoucherType.Equals(input.VoucherType))
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
                if (this.AccountId != null)
                {
                    hashCode = (hashCode * 59) + this.AccountId.GetHashCode();
                }
                if (this.ConsumptionDate != null)
                {
                    hashCode = (hashCode * 59) + this.ConsumptionDate.GetHashCode();
                }
                if (this.EmployeeId != null)
                {
                    hashCode = (hashCode * 59) + this.EmployeeId.GetHashCode();
                }
                if (this.EmployeeOpenId != null)
                {
                    hashCode = (hashCode * 59) + this.EmployeeOpenId.GetHashCode();
                }
                if (this.Extension != null)
                {
                    hashCode = (hashCode * 59) + this.Extension.GetHashCode();
                }
                if (this.GmtCreate != null)
                {
                    hashCode = (hashCode * 59) + this.GmtCreate.GetHashCode();
                }
                if (this.GmtModified != null)
                {
                    hashCode = (hashCode * 59) + this.GmtModified.GetHashCode();
                }
                if (this.Industry != null)
                {
                    hashCode = (hashCode * 59) + this.Industry.GetHashCode();
                }
                if (this.IsOffSet != null)
                {
                    hashCode = (hashCode * 59) + this.IsOffSet.GetHashCode();
                }
                if (this.Medium != null)
                {
                    hashCode = (hashCode * 59) + this.Medium.GetHashCode();
                }
                if (this.OuterSourceId != null)
                {
                    hashCode = (hashCode * 59) + this.OuterSourceId.GetHashCode();
                }
                if (this.ParentType != null)
                {
                    hashCode = (hashCode * 59) + this.ParentType.GetHashCode();
                }
                if (this.VoucherAmount != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherAmount.GetHashCode();
                }
                if (this.VoucherDate != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherDate.GetHashCode();
                }
                if (this.VoucherId != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherId.GetHashCode();
                }
                if (this.VoucherNo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherNo.GetHashCode();
                }
                if (this.VoucherState != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherState.GetHashCode();
                }
                if (this.VoucherType != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherType.GetHashCode();
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
