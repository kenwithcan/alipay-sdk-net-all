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
    /// AlipayCommerceEducateSchoolcardOrderSyncModel
    /// </summary>
    [DataContract(Name = "AlipayCommerceEducateSchoolcardOrderSyncModel")]
    public partial class AlipayCommerceEducateSchoolcardOrderSyncModel : IEquatable<AlipayCommerceEducateSchoolcardOrderSyncModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceEducateSchoolcardOrderSyncModel" /> class.
        /// </summary>
        /// <param name="actualAmount">实际金额（总支付金额），单位为【元】.</param>
        /// <param name="appletAppId">小程序appid.</param>
        /// <param name="cardBalance">校园卡余额.</param>
        /// <param name="cardNo">128.</param>
        /// <param name="cardType">校园卡类型.</param>
        /// <param name="createTime">该笔订单真实的创建时间，需精确到毫秒。.</param>
        /// <param name="discountAmount">优惠金额.</param>
        /// <param name="goodsOrders">goodsOrders.</param>
        /// <param name="merchantName">商家名称，不传默认展示学校名称.</param>
        /// <param name="modifiedTime">订单修改时间.</param>
        /// <param name="openId">用户open_id.</param>
        /// <param name="orderAmount">订单金额.</param>
        /// <param name="orderDetailUrl">订单详情链接.</param>
        /// <param name="orderStatus">订单状态.</param>
        /// <param name="outBizNo">外部业务号，由商家自定义，128个字符以内，仅支持字母、数字、下划线且需保证在商户端不重复。.</param>
        /// <param name="payAddress">支付地点.</param>
        /// <param name="payMode">付款方式，不传默认展示学校名称+校园卡+（卡号后四位）.</param>
        /// <param name="rakeBackPid">系统商编号。该参数作为系统商返佣数据提取的依据，请填写系统商签约协议的PID.</param>
        /// <param name="schoolId">学校内标，录入学校接口返回的参数.</param>
        /// <param name="schoolPid">学校收款账号.</param>
        /// <param name="serviceProviderName">服务提供者名称.</param>
        /// <param name="type">业务类型.</param>
        /// <param name="userId">买家支付宝用户ID。 2088开头的16位纯数字，小程序场景下获取用户ID请参考：用户授权; 其它场景下获取用户ID请参考：网页授权获取用户信息;.</param>
        public AlipayCommerceEducateSchoolcardOrderSyncModel(string actualAmount = default(string), string appletAppId = default(string), string cardBalance = default(string), string cardNo = default(string), string cardType = default(string), string createTime = default(string), string discountAmount = default(string), GoodsOrder goodsOrders = default(GoodsOrder), string merchantName = default(string), string modifiedTime = default(string), string openId = default(string), string orderAmount = default(string), string orderDetailUrl = default(string), string orderStatus = default(string), string outBizNo = default(string), string payAddress = default(string), string payMode = default(string), string rakeBackPid = default(string), string schoolId = default(string), string schoolPid = default(string), string serviceProviderName = default(string), string type = default(string), string userId = default(string))
        {
            this.ActualAmount = actualAmount;
            this.AppletAppId = appletAppId;
            this.CardBalance = cardBalance;
            this.CardNo = cardNo;
            this.CardType = cardType;
            this.CreateTime = createTime;
            this.DiscountAmount = discountAmount;
            this.GoodsOrders = goodsOrders;
            this.MerchantName = merchantName;
            this.ModifiedTime = modifiedTime;
            this.OpenId = openId;
            this.OrderAmount = orderAmount;
            this.OrderDetailUrl = orderDetailUrl;
            this.OrderStatus = orderStatus;
            this.OutBizNo = outBizNo;
            this.PayAddress = payAddress;
            this.PayMode = payMode;
            this.RakeBackPid = rakeBackPid;
            this.SchoolId = schoolId;
            this.SchoolPid = schoolPid;
            this.ServiceProviderName = serviceProviderName;
            this.Type = type;
            this.UserId = userId;
        }

        /// <summary>
        /// 实际金额（总支付金额），单位为【元】
        /// </summary>
        /// <value>实际金额（总支付金额），单位为【元】</value>
        [DataMember(Name = "actual_amount", EmitDefaultValue = false)]
        public string ActualAmount { get; set; }

        /// <summary>
        /// 小程序appid
        /// </summary>
        /// <value>小程序appid</value>
        [DataMember(Name = "applet_app_id", EmitDefaultValue = false)]
        public string AppletAppId { get; set; }

        /// <summary>
        /// 校园卡余额
        /// </summary>
        /// <value>校园卡余额</value>
        [DataMember(Name = "card_balance", EmitDefaultValue = false)]
        public string CardBalance { get; set; }

        /// <summary>
        /// 128
        /// </summary>
        /// <value>128</value>
        [DataMember(Name = "card_no", EmitDefaultValue = false)]
        public string CardNo { get; set; }

        /// <summary>
        /// 校园卡类型
        /// </summary>
        /// <value>校园卡类型</value>
        [DataMember(Name = "card_type", EmitDefaultValue = false)]
        public string CardType { get; set; }

        /// <summary>
        /// 该笔订单真实的创建时间，需精确到毫秒。
        /// </summary>
        /// <value>该笔订单真实的创建时间，需精确到毫秒。</value>
        [DataMember(Name = "create_time", EmitDefaultValue = false)]
        public string CreateTime { get; set; }

        /// <summary>
        /// 优惠金额
        /// </summary>
        /// <value>优惠金额</value>
        [DataMember(Name = "discount_amount", EmitDefaultValue = false)]
        public string DiscountAmount { get; set; }

        /// <summary>
        /// Gets or Sets GoodsOrders
        /// </summary>
        [DataMember(Name = "goods_orders", EmitDefaultValue = false)]
        public GoodsOrder GoodsOrders { get; set; }

        /// <summary>
        /// 商家名称，不传默认展示学校名称
        /// </summary>
        /// <value>商家名称，不传默认展示学校名称</value>
        [DataMember(Name = "merchant_name", EmitDefaultValue = false)]
        public string MerchantName { get; set; }

        /// <summary>
        /// 订单修改时间
        /// </summary>
        /// <value>订单修改时间</value>
        [DataMember(Name = "modified_time", EmitDefaultValue = false)]
        public string ModifiedTime { get; set; }

        /// <summary>
        /// 用户open_id
        /// </summary>
        /// <value>用户open_id</value>
        [DataMember(Name = "open_id", EmitDefaultValue = false)]
        public string OpenId { get; set; }

        /// <summary>
        /// 订单金额
        /// </summary>
        /// <value>订单金额</value>
        [DataMember(Name = "order_amount", EmitDefaultValue = false)]
        public string OrderAmount { get; set; }

        /// <summary>
        /// 订单详情链接
        /// </summary>
        /// <value>订单详情链接</value>
        [DataMember(Name = "order_detail_url", EmitDefaultValue = false)]
        public string OrderDetailUrl { get; set; }

        /// <summary>
        /// 订单状态
        /// </summary>
        /// <value>订单状态</value>
        [DataMember(Name = "order_status", EmitDefaultValue = false)]
        public string OrderStatus { get; set; }

        /// <summary>
        /// 外部业务号，由商家自定义，128个字符以内，仅支持字母、数字、下划线且需保证在商户端不重复。
        /// </summary>
        /// <value>外部业务号，由商家自定义，128个字符以内，仅支持字母、数字、下划线且需保证在商户端不重复。</value>
        [DataMember(Name = "out_biz_no", EmitDefaultValue = false)]
        public string OutBizNo { get; set; }

        /// <summary>
        /// 支付地点
        /// </summary>
        /// <value>支付地点</value>
        [DataMember(Name = "pay_address", EmitDefaultValue = false)]
        public string PayAddress { get; set; }

        /// <summary>
        /// 付款方式，不传默认展示学校名称+校园卡+（卡号后四位）
        /// </summary>
        /// <value>付款方式，不传默认展示学校名称+校园卡+（卡号后四位）</value>
        [DataMember(Name = "pay_mode", EmitDefaultValue = false)]
        public string PayMode { get; set; }

        /// <summary>
        /// 系统商编号。该参数作为系统商返佣数据提取的依据，请填写系统商签约协议的PID
        /// </summary>
        /// <value>系统商编号。该参数作为系统商返佣数据提取的依据，请填写系统商签约协议的PID</value>
        [DataMember(Name = "rake_back_pid", EmitDefaultValue = false)]
        public string RakeBackPid { get; set; }

        /// <summary>
        /// 学校内标，录入学校接口返回的参数
        /// </summary>
        /// <value>学校内标，录入学校接口返回的参数</value>
        [DataMember(Name = "school_id", EmitDefaultValue = false)]
        public string SchoolId { get; set; }

        /// <summary>
        /// 学校收款账号
        /// </summary>
        /// <value>学校收款账号</value>
        [DataMember(Name = "school_pid", EmitDefaultValue = false)]
        public string SchoolPid { get; set; }

        /// <summary>
        /// 服务提供者名称
        /// </summary>
        /// <value>服务提供者名称</value>
        [DataMember(Name = "service_provider_name", EmitDefaultValue = false)]
        public string ServiceProviderName { get; set; }

        /// <summary>
        /// 业务类型
        /// </summary>
        /// <value>业务类型</value>
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type { get; set; }

        /// <summary>
        /// 买家支付宝用户ID。 2088开头的16位纯数字，小程序场景下获取用户ID请参考：用户授权; 其它场景下获取用户ID请参考：网页授权获取用户信息;
        /// </summary>
        /// <value>买家支付宝用户ID。 2088开头的16位纯数字，小程序场景下获取用户ID请参考：用户授权; 其它场景下获取用户ID请参考：网页授权获取用户信息;</value>
        [DataMember(Name = "user_id", EmitDefaultValue = false)]
        public string UserId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayCommerceEducateSchoolcardOrderSyncModel {\n");
            sb.Append("  ActualAmount: ").Append(ActualAmount).Append("\n");
            sb.Append("  AppletAppId: ").Append(AppletAppId).Append("\n");
            sb.Append("  CardBalance: ").Append(CardBalance).Append("\n");
            sb.Append("  CardNo: ").Append(CardNo).Append("\n");
            sb.Append("  CardType: ").Append(CardType).Append("\n");
            sb.Append("  CreateTime: ").Append(CreateTime).Append("\n");
            sb.Append("  DiscountAmount: ").Append(DiscountAmount).Append("\n");
            sb.Append("  GoodsOrders: ").Append(GoodsOrders).Append("\n");
            sb.Append("  MerchantName: ").Append(MerchantName).Append("\n");
            sb.Append("  ModifiedTime: ").Append(ModifiedTime).Append("\n");
            sb.Append("  OpenId: ").Append(OpenId).Append("\n");
            sb.Append("  OrderAmount: ").Append(OrderAmount).Append("\n");
            sb.Append("  OrderDetailUrl: ").Append(OrderDetailUrl).Append("\n");
            sb.Append("  OrderStatus: ").Append(OrderStatus).Append("\n");
            sb.Append("  OutBizNo: ").Append(OutBizNo).Append("\n");
            sb.Append("  PayAddress: ").Append(PayAddress).Append("\n");
            sb.Append("  PayMode: ").Append(PayMode).Append("\n");
            sb.Append("  RakeBackPid: ").Append(RakeBackPid).Append("\n");
            sb.Append("  SchoolId: ").Append(SchoolId).Append("\n");
            sb.Append("  SchoolPid: ").Append(SchoolPid).Append("\n");
            sb.Append("  ServiceProviderName: ").Append(ServiceProviderName).Append("\n");
            sb.Append("  Type: ").Append(Type).Append("\n");
            sb.Append("  UserId: ").Append(UserId).Append("\n");
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
            return this.Equals(input as AlipayCommerceEducateSchoolcardOrderSyncModel);
        }

        /// <summary>
        /// Returns true if AlipayCommerceEducateSchoolcardOrderSyncModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayCommerceEducateSchoolcardOrderSyncModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayCommerceEducateSchoolcardOrderSyncModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ActualAmount == input.ActualAmount ||
                    (this.ActualAmount != null &&
                    this.ActualAmount.Equals(input.ActualAmount))
                ) && 
                (
                    this.AppletAppId == input.AppletAppId ||
                    (this.AppletAppId != null &&
                    this.AppletAppId.Equals(input.AppletAppId))
                ) && 
                (
                    this.CardBalance == input.CardBalance ||
                    (this.CardBalance != null &&
                    this.CardBalance.Equals(input.CardBalance))
                ) && 
                (
                    this.CardNo == input.CardNo ||
                    (this.CardNo != null &&
                    this.CardNo.Equals(input.CardNo))
                ) && 
                (
                    this.CardType == input.CardType ||
                    (this.CardType != null &&
                    this.CardType.Equals(input.CardType))
                ) && 
                (
                    this.CreateTime == input.CreateTime ||
                    (this.CreateTime != null &&
                    this.CreateTime.Equals(input.CreateTime))
                ) && 
                (
                    this.DiscountAmount == input.DiscountAmount ||
                    (this.DiscountAmount != null &&
                    this.DiscountAmount.Equals(input.DiscountAmount))
                ) && 
                (
                    this.GoodsOrders == input.GoodsOrders ||
                    (this.GoodsOrders != null &&
                    this.GoodsOrders.Equals(input.GoodsOrders))
                ) && 
                (
                    this.MerchantName == input.MerchantName ||
                    (this.MerchantName != null &&
                    this.MerchantName.Equals(input.MerchantName))
                ) && 
                (
                    this.ModifiedTime == input.ModifiedTime ||
                    (this.ModifiedTime != null &&
                    this.ModifiedTime.Equals(input.ModifiedTime))
                ) && 
                (
                    this.OpenId == input.OpenId ||
                    (this.OpenId != null &&
                    this.OpenId.Equals(input.OpenId))
                ) && 
                (
                    this.OrderAmount == input.OrderAmount ||
                    (this.OrderAmount != null &&
                    this.OrderAmount.Equals(input.OrderAmount))
                ) && 
                (
                    this.OrderDetailUrl == input.OrderDetailUrl ||
                    (this.OrderDetailUrl != null &&
                    this.OrderDetailUrl.Equals(input.OrderDetailUrl))
                ) && 
                (
                    this.OrderStatus == input.OrderStatus ||
                    (this.OrderStatus != null &&
                    this.OrderStatus.Equals(input.OrderStatus))
                ) && 
                (
                    this.OutBizNo == input.OutBizNo ||
                    (this.OutBizNo != null &&
                    this.OutBizNo.Equals(input.OutBizNo))
                ) && 
                (
                    this.PayAddress == input.PayAddress ||
                    (this.PayAddress != null &&
                    this.PayAddress.Equals(input.PayAddress))
                ) && 
                (
                    this.PayMode == input.PayMode ||
                    (this.PayMode != null &&
                    this.PayMode.Equals(input.PayMode))
                ) && 
                (
                    this.RakeBackPid == input.RakeBackPid ||
                    (this.RakeBackPid != null &&
                    this.RakeBackPid.Equals(input.RakeBackPid))
                ) && 
                (
                    this.SchoolId == input.SchoolId ||
                    (this.SchoolId != null &&
                    this.SchoolId.Equals(input.SchoolId))
                ) && 
                (
                    this.SchoolPid == input.SchoolPid ||
                    (this.SchoolPid != null &&
                    this.SchoolPid.Equals(input.SchoolPid))
                ) && 
                (
                    this.ServiceProviderName == input.ServiceProviderName ||
                    (this.ServiceProviderName != null &&
                    this.ServiceProviderName.Equals(input.ServiceProviderName))
                ) && 
                (
                    this.Type == input.Type ||
                    (this.Type != null &&
                    this.Type.Equals(input.Type))
                ) && 
                (
                    this.UserId == input.UserId ||
                    (this.UserId != null &&
                    this.UserId.Equals(input.UserId))
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
                if (this.ActualAmount != null)
                {
                    hashCode = (hashCode * 59) + this.ActualAmount.GetHashCode();
                }
                if (this.AppletAppId != null)
                {
                    hashCode = (hashCode * 59) + this.AppletAppId.GetHashCode();
                }
                if (this.CardBalance != null)
                {
                    hashCode = (hashCode * 59) + this.CardBalance.GetHashCode();
                }
                if (this.CardNo != null)
                {
                    hashCode = (hashCode * 59) + this.CardNo.GetHashCode();
                }
                if (this.CardType != null)
                {
                    hashCode = (hashCode * 59) + this.CardType.GetHashCode();
                }
                if (this.CreateTime != null)
                {
                    hashCode = (hashCode * 59) + this.CreateTime.GetHashCode();
                }
                if (this.DiscountAmount != null)
                {
                    hashCode = (hashCode * 59) + this.DiscountAmount.GetHashCode();
                }
                if (this.GoodsOrders != null)
                {
                    hashCode = (hashCode * 59) + this.GoodsOrders.GetHashCode();
                }
                if (this.MerchantName != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantName.GetHashCode();
                }
                if (this.ModifiedTime != null)
                {
                    hashCode = (hashCode * 59) + this.ModifiedTime.GetHashCode();
                }
                if (this.OpenId != null)
                {
                    hashCode = (hashCode * 59) + this.OpenId.GetHashCode();
                }
                if (this.OrderAmount != null)
                {
                    hashCode = (hashCode * 59) + this.OrderAmount.GetHashCode();
                }
                if (this.OrderDetailUrl != null)
                {
                    hashCode = (hashCode * 59) + this.OrderDetailUrl.GetHashCode();
                }
                if (this.OrderStatus != null)
                {
                    hashCode = (hashCode * 59) + this.OrderStatus.GetHashCode();
                }
                if (this.OutBizNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutBizNo.GetHashCode();
                }
                if (this.PayAddress != null)
                {
                    hashCode = (hashCode * 59) + this.PayAddress.GetHashCode();
                }
                if (this.PayMode != null)
                {
                    hashCode = (hashCode * 59) + this.PayMode.GetHashCode();
                }
                if (this.RakeBackPid != null)
                {
                    hashCode = (hashCode * 59) + this.RakeBackPid.GetHashCode();
                }
                if (this.SchoolId != null)
                {
                    hashCode = (hashCode * 59) + this.SchoolId.GetHashCode();
                }
                if (this.SchoolPid != null)
                {
                    hashCode = (hashCode * 59) + this.SchoolPid.GetHashCode();
                }
                if (this.ServiceProviderName != null)
                {
                    hashCode = (hashCode * 59) + this.ServiceProviderName.GetHashCode();
                }
                if (this.Type != null)
                {
                    hashCode = (hashCode * 59) + this.Type.GetHashCode();
                }
                if (this.UserId != null)
                {
                    hashCode = (hashCode * 59) + this.UserId.GetHashCode();
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
