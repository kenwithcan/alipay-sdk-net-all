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
    /// AlipayFundJointaccountDetailQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayFundJointaccountDetailQueryResponseModel")]
    public partial class AlipayFundJointaccountDetailQueryResponseModel : IEquatable<AlipayFundJointaccountDetailQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayFundJointaccountDetailQueryResponseModel" /> class.
        /// </summary>
        /// <param name="accountId">合花群ID（支付宝侧生成）.</param>
        /// <param name="accountName">账户名称（支付宝侧生成）.</param>
        /// <param name="accountQuota">额度模型.</param>
        /// <param name="accountStatus">账户状态&lt;br&gt; -NORMAL：正常&lt;br&gt; -RELEASING：注销中&lt;br&gt; -RELEASED：已注销&lt;br&gt; - FREEZE：冻结.</param>
        /// <param name="agreementNo">授权协议号（支付宝侧生成）.</param>
        /// <param name="authorizedRule">authorizedRule.</param>
        /// <param name="availableBalance">当前可用金额（单位为元，必须大于0且最多小数点后两位）.</param>
        /// <param name="bizScene">业务场景码.</param>
        /// <param name="creatorId">（创建人）支付宝侧用户唯一标识.</param>
        /// <param name="creatorOpenId">（创建人）支付宝侧用户唯一标识.</param>
        /// <param name="creatorOutId">（创建人）商户侧用户唯一标识&lt;br&gt; 补充说明：&lt;br&gt; -如果签约时，发起人标识传递的是商户侧用户唯一标识，则该字段会返回&lt;br&gt; -如果签约时，发起人标识传递的是支付宝侧用户唯一标识，则该字段为空.</param>
        /// <param name="freezeBalance">当前冻结金额（单位为元，必须大于0且最多小数点后两位）.</param>
        /// <param name="inviteResultList">签约时邀请的成员列表（快照）.</param>
        /// <param name="memberList">已加入合花群的成员列表.</param>
        /// <param name="productCode">销售产品码.</param>
        /// <param name="profitStatus">生息状态：&lt;/br&gt; - MAKING    ：开启中&lt;/br&gt; - MADE.       ：已开启&lt;/br&gt; - CLEARING：关闭中&lt;/br&gt; - NONE.       ：未生息.</param>
        /// <param name="yesterdayProfit">昨日收益.</param>
        public AlipayFundJointaccountDetailQueryResponseModel(string accountId = default(string), string accountName = default(string), List<JointAccountQuotaRespDTO> accountQuota = default(List<JointAccountQuotaRespDTO>), string accountStatus = default(string), string agreementNo = default(string), AuthorizedRuleDTO authorizedRule = default(AuthorizedRuleDTO), string availableBalance = default(string), string bizScene = default(string), string creatorId = default(string), string creatorOpenId = default(string), string creatorOutId = default(string), string freezeBalance = default(string), List<InviteResultDTO> inviteResultList = default(List<InviteResultDTO>), List<JointAccountMemberInfoRespDTO> memberList = default(List<JointAccountMemberInfoRespDTO>), string productCode = default(string), string profitStatus = default(string), string yesterdayProfit = default(string))
        {
            this.AccountId = accountId;
            this.AccountName = accountName;
            this.AccountQuota = accountQuota;
            this.AccountStatus = accountStatus;
            this.AgreementNo = agreementNo;
            this.AuthorizedRule = authorizedRule;
            this.AvailableBalance = availableBalance;
            this.BizScene = bizScene;
            this.CreatorId = creatorId;
            this.CreatorOpenId = creatorOpenId;
            this.CreatorOutId = creatorOutId;
            this.FreezeBalance = freezeBalance;
            this.InviteResultList = inviteResultList;
            this.MemberList = memberList;
            this.ProductCode = productCode;
            this.ProfitStatus = profitStatus;
            this.YesterdayProfit = yesterdayProfit;
        }

        /// <summary>
        /// 合花群ID（支付宝侧生成）
        /// </summary>
        /// <value>合花群ID（支付宝侧生成）</value>
        [DataMember(Name = "account_id", EmitDefaultValue = false)]
        public string AccountId { get; set; }

        /// <summary>
        /// 账户名称（支付宝侧生成）
        /// </summary>
        /// <value>账户名称（支付宝侧生成）</value>
        [DataMember(Name = "account_name", EmitDefaultValue = false)]
        public string AccountName { get; set; }

        /// <summary>
        /// 额度模型
        /// </summary>
        /// <value>额度模型</value>
        [DataMember(Name = "account_quota", EmitDefaultValue = false)]
        public List<JointAccountQuotaRespDTO> AccountQuota { get; set; }

        /// <summary>
        /// 账户状态&lt;br&gt; -NORMAL：正常&lt;br&gt; -RELEASING：注销中&lt;br&gt; -RELEASED：已注销&lt;br&gt; - FREEZE：冻结
        /// </summary>
        /// <value>账户状态&lt;br&gt; -NORMAL：正常&lt;br&gt; -RELEASING：注销中&lt;br&gt; -RELEASED：已注销&lt;br&gt; - FREEZE：冻结</value>
        [DataMember(Name = "account_status", EmitDefaultValue = false)]
        public string AccountStatus { get; set; }

        /// <summary>
        /// 授权协议号（支付宝侧生成）
        /// </summary>
        /// <value>授权协议号（支付宝侧生成）</value>
        [DataMember(Name = "agreement_no", EmitDefaultValue = false)]
        public string AgreementNo { get; set; }

        /// <summary>
        /// Gets or Sets AuthorizedRule
        /// </summary>
        [DataMember(Name = "authorized_rule", EmitDefaultValue = false)]
        public AuthorizedRuleDTO AuthorizedRule { get; set; }

        /// <summary>
        /// 当前可用金额（单位为元，必须大于0且最多小数点后两位）
        /// </summary>
        /// <value>当前可用金额（单位为元，必须大于0且最多小数点后两位）</value>
        [DataMember(Name = "available_balance", EmitDefaultValue = false)]
        public string AvailableBalance { get; set; }

        /// <summary>
        /// 业务场景码
        /// </summary>
        /// <value>业务场景码</value>
        [DataMember(Name = "biz_scene", EmitDefaultValue = false)]
        public string BizScene { get; set; }

        /// <summary>
        /// （创建人）支付宝侧用户唯一标识
        /// </summary>
        /// <value>（创建人）支付宝侧用户唯一标识</value>
        [DataMember(Name = "creator_id", EmitDefaultValue = false)]
        public string CreatorId { get; set; }

        /// <summary>
        /// （创建人）支付宝侧用户唯一标识
        /// </summary>
        /// <value>（创建人）支付宝侧用户唯一标识</value>
        [DataMember(Name = "creator_open_id", EmitDefaultValue = false)]
        public string CreatorOpenId { get; set; }

        /// <summary>
        /// （创建人）商户侧用户唯一标识&lt;br&gt; 补充说明：&lt;br&gt; -如果签约时，发起人标识传递的是商户侧用户唯一标识，则该字段会返回&lt;br&gt; -如果签约时，发起人标识传递的是支付宝侧用户唯一标识，则该字段为空
        /// </summary>
        /// <value>（创建人）商户侧用户唯一标识&lt;br&gt; 补充说明：&lt;br&gt; -如果签约时，发起人标识传递的是商户侧用户唯一标识，则该字段会返回&lt;br&gt; -如果签约时，发起人标识传递的是支付宝侧用户唯一标识，则该字段为空</value>
        [DataMember(Name = "creator_out_id", EmitDefaultValue = false)]
        public string CreatorOutId { get; set; }

        /// <summary>
        /// 当前冻结金额（单位为元，必须大于0且最多小数点后两位）
        /// </summary>
        /// <value>当前冻结金额（单位为元，必须大于0且最多小数点后两位）</value>
        [DataMember(Name = "freeze_balance", EmitDefaultValue = false)]
        public string FreezeBalance { get; set; }

        /// <summary>
        /// 签约时邀请的成员列表（快照）
        /// </summary>
        /// <value>签约时邀请的成员列表（快照）</value>
        [DataMember(Name = "invite_result_list", EmitDefaultValue = false)]
        public List<InviteResultDTO> InviteResultList { get; set; }

        /// <summary>
        /// 已加入合花群的成员列表
        /// </summary>
        /// <value>已加入合花群的成员列表</value>
        [DataMember(Name = "member_list", EmitDefaultValue = false)]
        public List<JointAccountMemberInfoRespDTO> MemberList { get; set; }

        /// <summary>
        /// 销售产品码
        /// </summary>
        /// <value>销售产品码</value>
        [DataMember(Name = "product_code", EmitDefaultValue = false)]
        public string ProductCode { get; set; }

        /// <summary>
        /// 生息状态：&lt;/br&gt; - MAKING    ：开启中&lt;/br&gt; - MADE.       ：已开启&lt;/br&gt; - CLEARING：关闭中&lt;/br&gt; - NONE.       ：未生息
        /// </summary>
        /// <value>生息状态：&lt;/br&gt; - MAKING    ：开启中&lt;/br&gt; - MADE.       ：已开启&lt;/br&gt; - CLEARING：关闭中&lt;/br&gt; - NONE.       ：未生息</value>
        [DataMember(Name = "profit_status", EmitDefaultValue = false)]
        public string ProfitStatus { get; set; }

        /// <summary>
        /// 昨日收益
        /// </summary>
        /// <value>昨日收益</value>
        [DataMember(Name = "yesterday_profit", EmitDefaultValue = false)]
        public string YesterdayProfit { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayFundJointaccountDetailQueryResponseModel {\n");
            sb.Append("  AccountId: ").Append(AccountId).Append("\n");
            sb.Append("  AccountName: ").Append(AccountName).Append("\n");
            sb.Append("  AccountQuota: ").Append(AccountQuota).Append("\n");
            sb.Append("  AccountStatus: ").Append(AccountStatus).Append("\n");
            sb.Append("  AgreementNo: ").Append(AgreementNo).Append("\n");
            sb.Append("  AuthorizedRule: ").Append(AuthorizedRule).Append("\n");
            sb.Append("  AvailableBalance: ").Append(AvailableBalance).Append("\n");
            sb.Append("  BizScene: ").Append(BizScene).Append("\n");
            sb.Append("  CreatorId: ").Append(CreatorId).Append("\n");
            sb.Append("  CreatorOpenId: ").Append(CreatorOpenId).Append("\n");
            sb.Append("  CreatorOutId: ").Append(CreatorOutId).Append("\n");
            sb.Append("  FreezeBalance: ").Append(FreezeBalance).Append("\n");
            sb.Append("  InviteResultList: ").Append(InviteResultList).Append("\n");
            sb.Append("  MemberList: ").Append(MemberList).Append("\n");
            sb.Append("  ProductCode: ").Append(ProductCode).Append("\n");
            sb.Append("  ProfitStatus: ").Append(ProfitStatus).Append("\n");
            sb.Append("  YesterdayProfit: ").Append(YesterdayProfit).Append("\n");
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
            return this.Equals(input as AlipayFundJointaccountDetailQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayFundJointaccountDetailQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayFundJointaccountDetailQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayFundJointaccountDetailQueryResponseModel input)
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
                    this.AccountName == input.AccountName ||
                    (this.AccountName != null &&
                    this.AccountName.Equals(input.AccountName))
                ) && 
                (
                    this.AccountQuota == input.AccountQuota ||
                    this.AccountQuota != null &&
                    input.AccountQuota != null &&
                    this.AccountQuota.SequenceEqual(input.AccountQuota)
                ) && 
                (
                    this.AccountStatus == input.AccountStatus ||
                    (this.AccountStatus != null &&
                    this.AccountStatus.Equals(input.AccountStatus))
                ) && 
                (
                    this.AgreementNo == input.AgreementNo ||
                    (this.AgreementNo != null &&
                    this.AgreementNo.Equals(input.AgreementNo))
                ) && 
                (
                    this.AuthorizedRule == input.AuthorizedRule ||
                    (this.AuthorizedRule != null &&
                    this.AuthorizedRule.Equals(input.AuthorizedRule))
                ) && 
                (
                    this.AvailableBalance == input.AvailableBalance ||
                    (this.AvailableBalance != null &&
                    this.AvailableBalance.Equals(input.AvailableBalance))
                ) && 
                (
                    this.BizScene == input.BizScene ||
                    (this.BizScene != null &&
                    this.BizScene.Equals(input.BizScene))
                ) && 
                (
                    this.CreatorId == input.CreatorId ||
                    (this.CreatorId != null &&
                    this.CreatorId.Equals(input.CreatorId))
                ) && 
                (
                    this.CreatorOpenId == input.CreatorOpenId ||
                    (this.CreatorOpenId != null &&
                    this.CreatorOpenId.Equals(input.CreatorOpenId))
                ) && 
                (
                    this.CreatorOutId == input.CreatorOutId ||
                    (this.CreatorOutId != null &&
                    this.CreatorOutId.Equals(input.CreatorOutId))
                ) && 
                (
                    this.FreezeBalance == input.FreezeBalance ||
                    (this.FreezeBalance != null &&
                    this.FreezeBalance.Equals(input.FreezeBalance))
                ) && 
                (
                    this.InviteResultList == input.InviteResultList ||
                    this.InviteResultList != null &&
                    input.InviteResultList != null &&
                    this.InviteResultList.SequenceEqual(input.InviteResultList)
                ) && 
                (
                    this.MemberList == input.MemberList ||
                    this.MemberList != null &&
                    input.MemberList != null &&
                    this.MemberList.SequenceEqual(input.MemberList)
                ) && 
                (
                    this.ProductCode == input.ProductCode ||
                    (this.ProductCode != null &&
                    this.ProductCode.Equals(input.ProductCode))
                ) && 
                (
                    this.ProfitStatus == input.ProfitStatus ||
                    (this.ProfitStatus != null &&
                    this.ProfitStatus.Equals(input.ProfitStatus))
                ) && 
                (
                    this.YesterdayProfit == input.YesterdayProfit ||
                    (this.YesterdayProfit != null &&
                    this.YesterdayProfit.Equals(input.YesterdayProfit))
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
                if (this.AccountName != null)
                {
                    hashCode = (hashCode * 59) + this.AccountName.GetHashCode();
                }
                if (this.AccountQuota != null)
                {
                    hashCode = (hashCode * 59) + this.AccountQuota.GetHashCode();
                }
                if (this.AccountStatus != null)
                {
                    hashCode = (hashCode * 59) + this.AccountStatus.GetHashCode();
                }
                if (this.AgreementNo != null)
                {
                    hashCode = (hashCode * 59) + this.AgreementNo.GetHashCode();
                }
                if (this.AuthorizedRule != null)
                {
                    hashCode = (hashCode * 59) + this.AuthorizedRule.GetHashCode();
                }
                if (this.AvailableBalance != null)
                {
                    hashCode = (hashCode * 59) + this.AvailableBalance.GetHashCode();
                }
                if (this.BizScene != null)
                {
                    hashCode = (hashCode * 59) + this.BizScene.GetHashCode();
                }
                if (this.CreatorId != null)
                {
                    hashCode = (hashCode * 59) + this.CreatorId.GetHashCode();
                }
                if (this.CreatorOpenId != null)
                {
                    hashCode = (hashCode * 59) + this.CreatorOpenId.GetHashCode();
                }
                if (this.CreatorOutId != null)
                {
                    hashCode = (hashCode * 59) + this.CreatorOutId.GetHashCode();
                }
                if (this.FreezeBalance != null)
                {
                    hashCode = (hashCode * 59) + this.FreezeBalance.GetHashCode();
                }
                if (this.InviteResultList != null)
                {
                    hashCode = (hashCode * 59) + this.InviteResultList.GetHashCode();
                }
                if (this.MemberList != null)
                {
                    hashCode = (hashCode * 59) + this.MemberList.GetHashCode();
                }
                if (this.ProductCode != null)
                {
                    hashCode = (hashCode * 59) + this.ProductCode.GetHashCode();
                }
                if (this.ProfitStatus != null)
                {
                    hashCode = (hashCode * 59) + this.ProfitStatus.GetHashCode();
                }
                if (this.YesterdayProfit != null)
                {
                    hashCode = (hashCode * 59) + this.YesterdayProfit.GetHashCode();
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
