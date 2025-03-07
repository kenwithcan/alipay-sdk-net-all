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
    /// RecruitVoucherRule
    /// </summary>
    [DataContract(Name = "RecruitVoucherRule")]
    public partial class RecruitVoucherRule : IEquatable<RecruitVoucherRule>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RecruitVoucherRule" /> class.
        /// </summary>
        /// <param name="amountMax">券面额（每张代金券可以抵扣的金额）的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="amountMin">券面额（每张代金券可以抵扣的金额）的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="denominationPercentMax">券优惠比例的最大值。20代表优惠比例最多是20%。券优惠券比例&#x3D;券优惠面额/门槛金额。 浮点类型，取值范围为[1,100]，左右均是闭区间，小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="denominationPercentMin">券优惠比例的最小值。10代表优惠比例最少是10%。券优惠券比例&#x3D;券优惠面额/门槛金额。 浮点类型，取值范围为[1,100]，左右均是闭区间，小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="floorAmountMax">券门槛金额的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="floorAmountMin">券门槛金额的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="originAmountMax">券原价的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="originAmountMin">券原价的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="publishEndTimeMax">券发放结束时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。.</param>
        /// <param name="publishEndTimeMin">券发放结束时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。.</param>
        /// <param name="publishStartTimeMax">券发放开始时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。.</param>
        /// <param name="publishStartTimeMin">券发放开始时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。.</param>
        /// <param name="refundType">退券类型要求，列表，总共有两种类型： 过期退OVERDUE_REFUND 随时退CAN_REFUND 该字段为空时表示不限制。.</param>
        /// <param name="saleAmountMax">用户购买优惠券需要支付的金额的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="saleAmountMin">用户购买优惠券需要支付的金额的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。.</param>
        /// <param name="useChannel">券核销渠道要求，列表，总共有两个渠道： 门店SHOP 小程序MINI_APP 该字段为空时表示不限制。.</param>
        /// <param name="validDaysAfterReceiveMin">券生效后至少N天内可以使用。比如：valid_days_after_receive_min&#x3D;20代表 券生效后至少20天内可以使用。 该字段为空时表示不限制。.</param>
        /// <param name="voucherActivityType">券活动类型。支持七种商家券类型和两种支付券类型。  枚举值： 商家券类型： ALL_FIX_ORDER_VOUCHER 全场满减券； ITEM_FIX_ORDER_VOUCHER 单品满减券； ALL_DISCOUNT_ORDER_VOUCHER 全场折扣券； ITEM_DISCOUNT_ORDER_VOUCHER 单品折扣券； ITEM_SPE_ORDER_VOUCHER 单品特价券； EXCHANGE_GROUP_BUY_ORDER_VOUCHER 兑换团购券； EXCHANGE_FIX_ORDER_VOUCHER 兑换代金券；  支付券类型： ALL_FIX_VOUCHER 全场满减券； ITEM_FIX_VOUCHER 单品满减券；  创建商家券参考https://opendocs.alipay.com/apis/01xm17 创建支付券参考https://opendocs.alipay.com/pre-apis/027185（仅供受邀用户使用） 不同的创建券的参数创建出不同类型的券：  1. 根据voucher_type区分满减券、折扣券、特价券、兑换券  2. 根据goods_name是否为空区分单品券、全场券（当voucher_type为满减券、折扣券、特价券）  3. 根据voucher_use_rule.exchange_voucher.biz_type区分团购券、代金券（当voucher_type为兑换券）.</param>
        /// <param name="voucherQuantityLimitPerUserMax">每人领取限制的最大值。 默认按照支付宝uid进行领取限制。 该字段为空时表示不限制。.</param>
        /// <param name="voucherQuantityLimitPerUserMin">每人领取限制的最小值。 默认按照支付宝uid进行领取限制。 该字段为空时表示不限制。.</param>
        /// <param name="voucherQuantityMax">券库存数量的最大值。 该字段为空时表示不限制。.</param>
        /// <param name="voucherQuantityMin">券库存数量的最小值。 该字段为空时表示不限制。.</param>
        /// <param name="voucherValidBeginTimeMin">券可使用的开始时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。.</param>
        /// <param name="voucherValidEndTimeMax">券可使用的结束时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。.</param>
        public RecruitVoucherRule(string amountMax = default(string), string amountMin = default(string), string denominationPercentMax = default(string), string denominationPercentMin = default(string), string floorAmountMax = default(string), string floorAmountMin = default(string), string originAmountMax = default(string), string originAmountMin = default(string), string publishEndTimeMax = default(string), string publishEndTimeMin = default(string), string publishStartTimeMax = default(string), string publishStartTimeMin = default(string), List<string> refundType = default(List<string>), string saleAmountMax = default(string), string saleAmountMin = default(string), List<string> useChannel = default(List<string>), int validDaysAfterReceiveMin = default(int), string voucherActivityType = default(string), int voucherQuantityLimitPerUserMax = default(int), int voucherQuantityLimitPerUserMin = default(int), int voucherQuantityMax = default(int), int voucherQuantityMin = default(int), string voucherValidBeginTimeMin = default(string), string voucherValidEndTimeMax = default(string))
        {
            this.AmountMax = amountMax;
            this.AmountMin = amountMin;
            this.DenominationPercentMax = denominationPercentMax;
            this.DenominationPercentMin = denominationPercentMin;
            this.FloorAmountMax = floorAmountMax;
            this.FloorAmountMin = floorAmountMin;
            this.OriginAmountMax = originAmountMax;
            this.OriginAmountMin = originAmountMin;
            this.PublishEndTimeMax = publishEndTimeMax;
            this.PublishEndTimeMin = publishEndTimeMin;
            this.PublishStartTimeMax = publishStartTimeMax;
            this.PublishStartTimeMin = publishStartTimeMin;
            this.RefundType = refundType;
            this.SaleAmountMax = saleAmountMax;
            this.SaleAmountMin = saleAmountMin;
            this.UseChannel = useChannel;
            this.ValidDaysAfterReceiveMin = validDaysAfterReceiveMin;
            this.VoucherActivityType = voucherActivityType;
            this.VoucherQuantityLimitPerUserMax = voucherQuantityLimitPerUserMax;
            this.VoucherQuantityLimitPerUserMin = voucherQuantityLimitPerUserMin;
            this.VoucherQuantityMax = voucherQuantityMax;
            this.VoucherQuantityMin = voucherQuantityMin;
            this.VoucherValidBeginTimeMin = voucherValidBeginTimeMin;
            this.VoucherValidEndTimeMax = voucherValidEndTimeMax;
        }

        /// <summary>
        /// 券面额（每张代金券可以抵扣的金额）的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券面额（每张代金券可以抵扣的金额）的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "amount_max", EmitDefaultValue = false)]
        public string AmountMax { get; set; }

        /// <summary>
        /// 券面额（每张代金券可以抵扣的金额）的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券面额（每张代金券可以抵扣的金额）的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "amount_min", EmitDefaultValue = false)]
        public string AmountMin { get; set; }

        /// <summary>
        /// 券优惠比例的最大值。20代表优惠比例最多是20%。券优惠券比例&#x3D;券优惠面额/门槛金额。 浮点类型，取值范围为[1,100]，左右均是闭区间，小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券优惠比例的最大值。20代表优惠比例最多是20%。券优惠券比例&#x3D;券优惠面额/门槛金额。 浮点类型，取值范围为[1,100]，左右均是闭区间，小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "denomination_percent_max", EmitDefaultValue = false)]
        public string DenominationPercentMax { get; set; }

        /// <summary>
        /// 券优惠比例的最小值。10代表优惠比例最少是10%。券优惠券比例&#x3D;券优惠面额/门槛金额。 浮点类型，取值范围为[1,100]，左右均是闭区间，小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券优惠比例的最小值。10代表优惠比例最少是10%。券优惠券比例&#x3D;券优惠面额/门槛金额。 浮点类型，取值范围为[1,100]，左右均是闭区间，小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "denomination_percent_min", EmitDefaultValue = false)]
        public string DenominationPercentMin { get; set; }

        /// <summary>
        /// 券门槛金额的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券门槛金额的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "floor_amount_max", EmitDefaultValue = false)]
        public string FloorAmountMax { get; set; }

        /// <summary>
        /// 券门槛金额的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券门槛金额的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "floor_amount_min", EmitDefaultValue = false)]
        public string FloorAmountMin { get; set; }

        /// <summary>
        /// 券原价的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券原价的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "origin_amount_max", EmitDefaultValue = false)]
        public string OriginAmountMax { get; set; }

        /// <summary>
        /// 券原价的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券原价的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "origin_amount_min", EmitDefaultValue = false)]
        public string OriginAmountMin { get; set; }

        /// <summary>
        /// 券发放结束时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。
        /// </summary>
        /// <value>券发放结束时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。</value>
        [DataMember(Name = "publish_end_time_max", EmitDefaultValue = false)]
        public string PublishEndTimeMax { get; set; }

        /// <summary>
        /// 券发放结束时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。
        /// </summary>
        /// <value>券发放结束时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。</value>
        [DataMember(Name = "publish_end_time_min", EmitDefaultValue = false)]
        public string PublishEndTimeMin { get; set; }

        /// <summary>
        /// 券发放开始时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。
        /// </summary>
        /// <value>券发放开始时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。</value>
        [DataMember(Name = "publish_start_time_max", EmitDefaultValue = false)]
        public string PublishStartTimeMax { get; set; }

        /// <summary>
        /// 券发放开始时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。
        /// </summary>
        /// <value>券发放开始时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。</value>
        [DataMember(Name = "publish_start_time_min", EmitDefaultValue = false)]
        public string PublishStartTimeMin { get; set; }

        /// <summary>
        /// 退券类型要求，列表，总共有两种类型： 过期退OVERDUE_REFUND 随时退CAN_REFUND 该字段为空时表示不限制。
        /// </summary>
        /// <value>退券类型要求，列表，总共有两种类型： 过期退OVERDUE_REFUND 随时退CAN_REFUND 该字段为空时表示不限制。</value>
        [DataMember(Name = "refund_type", EmitDefaultValue = false)]
        public List<string> RefundType { get; set; }

        /// <summary>
        /// 用户购买优惠券需要支付的金额的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>用户购买优惠券需要支付的金额的最大值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "sale_amount_max", EmitDefaultValue = false)]
        public string SaleAmountMax { get; set; }

        /// <summary>
        /// 用户购买优惠券需要支付的金额的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。
        /// </summary>
        /// <value>用户购买优惠券需要支付的金额的最小值。 币种为人民币，单位为元。小数点以后最多保留两位。 该字段为空时表示不限制。</value>
        [DataMember(Name = "sale_amount_min", EmitDefaultValue = false)]
        public string SaleAmountMin { get; set; }

        /// <summary>
        /// 券核销渠道要求，列表，总共有两个渠道： 门店SHOP 小程序MINI_APP 该字段为空时表示不限制。
        /// </summary>
        /// <value>券核销渠道要求，列表，总共有两个渠道： 门店SHOP 小程序MINI_APP 该字段为空时表示不限制。</value>
        [DataMember(Name = "use_channel", EmitDefaultValue = false)]
        public List<string> UseChannel { get; set; }

        /// <summary>
        /// 券生效后至少N天内可以使用。比如：valid_days_after_receive_min&#x3D;20代表 券生效后至少20天内可以使用。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券生效后至少N天内可以使用。比如：valid_days_after_receive_min&#x3D;20代表 券生效后至少20天内可以使用。 该字段为空时表示不限制。</value>
        [DataMember(Name = "valid_days_after_receive_min", EmitDefaultValue = false)]
        public int ValidDaysAfterReceiveMin { get; set; }

        /// <summary>
        /// 券活动类型。支持七种商家券类型和两种支付券类型。  枚举值： 商家券类型： ALL_FIX_ORDER_VOUCHER 全场满减券； ITEM_FIX_ORDER_VOUCHER 单品满减券； ALL_DISCOUNT_ORDER_VOUCHER 全场折扣券； ITEM_DISCOUNT_ORDER_VOUCHER 单品折扣券； ITEM_SPE_ORDER_VOUCHER 单品特价券； EXCHANGE_GROUP_BUY_ORDER_VOUCHER 兑换团购券； EXCHANGE_FIX_ORDER_VOUCHER 兑换代金券；  支付券类型： ALL_FIX_VOUCHER 全场满减券； ITEM_FIX_VOUCHER 单品满减券；  创建商家券参考https://opendocs.alipay.com/apis/01xm17 创建支付券参考https://opendocs.alipay.com/pre-apis/027185（仅供受邀用户使用） 不同的创建券的参数创建出不同类型的券：  1. 根据voucher_type区分满减券、折扣券、特价券、兑换券  2. 根据goods_name是否为空区分单品券、全场券（当voucher_type为满减券、折扣券、特价券）  3. 根据voucher_use_rule.exchange_voucher.biz_type区分团购券、代金券（当voucher_type为兑换券）
        /// </summary>
        /// <value>券活动类型。支持七种商家券类型和两种支付券类型。  枚举值： 商家券类型： ALL_FIX_ORDER_VOUCHER 全场满减券； ITEM_FIX_ORDER_VOUCHER 单品满减券； ALL_DISCOUNT_ORDER_VOUCHER 全场折扣券； ITEM_DISCOUNT_ORDER_VOUCHER 单品折扣券； ITEM_SPE_ORDER_VOUCHER 单品特价券； EXCHANGE_GROUP_BUY_ORDER_VOUCHER 兑换团购券； EXCHANGE_FIX_ORDER_VOUCHER 兑换代金券；  支付券类型： ALL_FIX_VOUCHER 全场满减券； ITEM_FIX_VOUCHER 单品满减券；  创建商家券参考https://opendocs.alipay.com/apis/01xm17 创建支付券参考https://opendocs.alipay.com/pre-apis/027185（仅供受邀用户使用） 不同的创建券的参数创建出不同类型的券：  1. 根据voucher_type区分满减券、折扣券、特价券、兑换券  2. 根据goods_name是否为空区分单品券、全场券（当voucher_type为满减券、折扣券、特价券）  3. 根据voucher_use_rule.exchange_voucher.biz_type区分团购券、代金券（当voucher_type为兑换券）</value>
        [DataMember(Name = "voucher_activity_type", EmitDefaultValue = false)]
        public string VoucherActivityType { get; set; }

        /// <summary>
        /// 每人领取限制的最大值。 默认按照支付宝uid进行领取限制。 该字段为空时表示不限制。
        /// </summary>
        /// <value>每人领取限制的最大值。 默认按照支付宝uid进行领取限制。 该字段为空时表示不限制。</value>
        [DataMember(Name = "voucher_quantity_limit_per_user_max", EmitDefaultValue = false)]
        public int VoucherQuantityLimitPerUserMax { get; set; }

        /// <summary>
        /// 每人领取限制的最小值。 默认按照支付宝uid进行领取限制。 该字段为空时表示不限制。
        /// </summary>
        /// <value>每人领取限制的最小值。 默认按照支付宝uid进行领取限制。 该字段为空时表示不限制。</value>
        [DataMember(Name = "voucher_quantity_limit_per_user_min", EmitDefaultValue = false)]
        public int VoucherQuantityLimitPerUserMin { get; set; }

        /// <summary>
        /// 券库存数量的最大值。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券库存数量的最大值。 该字段为空时表示不限制。</value>
        [DataMember(Name = "voucher_quantity_max", EmitDefaultValue = false)]
        public int VoucherQuantityMax { get; set; }

        /// <summary>
        /// 券库存数量的最小值。 该字段为空时表示不限制。
        /// </summary>
        /// <value>券库存数量的最小值。 该字段为空时表示不限制。</value>
        [DataMember(Name = "voucher_quantity_min", EmitDefaultValue = false)]
        public int VoucherQuantityMin { get; set; }

        /// <summary>
        /// 券可使用的开始时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。
        /// </summary>
        /// <value>券可使用的开始时间的最小值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。</value>
        [DataMember(Name = "voucher_valid_begin_time_min", EmitDefaultValue = false)]
        public string VoucherValidBeginTimeMin { get; set; }

        /// <summary>
        /// 券可使用的结束时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。
        /// </summary>
        /// <value>券可使用的结束时间的最大值。 格式为：yyyy-MM-dd HH:mm:ss 该字段为空时表示不限制。</value>
        [DataMember(Name = "voucher_valid_end_time_max", EmitDefaultValue = false)]
        public string VoucherValidEndTimeMax { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class RecruitVoucherRule {\n");
            sb.Append("  AmountMax: ").Append(AmountMax).Append("\n");
            sb.Append("  AmountMin: ").Append(AmountMin).Append("\n");
            sb.Append("  DenominationPercentMax: ").Append(DenominationPercentMax).Append("\n");
            sb.Append("  DenominationPercentMin: ").Append(DenominationPercentMin).Append("\n");
            sb.Append("  FloorAmountMax: ").Append(FloorAmountMax).Append("\n");
            sb.Append("  FloorAmountMin: ").Append(FloorAmountMin).Append("\n");
            sb.Append("  OriginAmountMax: ").Append(OriginAmountMax).Append("\n");
            sb.Append("  OriginAmountMin: ").Append(OriginAmountMin).Append("\n");
            sb.Append("  PublishEndTimeMax: ").Append(PublishEndTimeMax).Append("\n");
            sb.Append("  PublishEndTimeMin: ").Append(PublishEndTimeMin).Append("\n");
            sb.Append("  PublishStartTimeMax: ").Append(PublishStartTimeMax).Append("\n");
            sb.Append("  PublishStartTimeMin: ").Append(PublishStartTimeMin).Append("\n");
            sb.Append("  RefundType: ").Append(RefundType).Append("\n");
            sb.Append("  SaleAmountMax: ").Append(SaleAmountMax).Append("\n");
            sb.Append("  SaleAmountMin: ").Append(SaleAmountMin).Append("\n");
            sb.Append("  UseChannel: ").Append(UseChannel).Append("\n");
            sb.Append("  ValidDaysAfterReceiveMin: ").Append(ValidDaysAfterReceiveMin).Append("\n");
            sb.Append("  VoucherActivityType: ").Append(VoucherActivityType).Append("\n");
            sb.Append("  VoucherQuantityLimitPerUserMax: ").Append(VoucherQuantityLimitPerUserMax).Append("\n");
            sb.Append("  VoucherQuantityLimitPerUserMin: ").Append(VoucherQuantityLimitPerUserMin).Append("\n");
            sb.Append("  VoucherQuantityMax: ").Append(VoucherQuantityMax).Append("\n");
            sb.Append("  VoucherQuantityMin: ").Append(VoucherQuantityMin).Append("\n");
            sb.Append("  VoucherValidBeginTimeMin: ").Append(VoucherValidBeginTimeMin).Append("\n");
            sb.Append("  VoucherValidEndTimeMax: ").Append(VoucherValidEndTimeMax).Append("\n");
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
            return this.Equals(input as RecruitVoucherRule);
        }

        /// <summary>
        /// Returns true if RecruitVoucherRule instances are equal
        /// </summary>
        /// <param name="input">Instance of RecruitVoucherRule to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(RecruitVoucherRule input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AmountMax == input.AmountMax ||
                    (this.AmountMax != null &&
                    this.AmountMax.Equals(input.AmountMax))
                ) && 
                (
                    this.AmountMin == input.AmountMin ||
                    (this.AmountMin != null &&
                    this.AmountMin.Equals(input.AmountMin))
                ) && 
                (
                    this.DenominationPercentMax == input.DenominationPercentMax ||
                    (this.DenominationPercentMax != null &&
                    this.DenominationPercentMax.Equals(input.DenominationPercentMax))
                ) && 
                (
                    this.DenominationPercentMin == input.DenominationPercentMin ||
                    (this.DenominationPercentMin != null &&
                    this.DenominationPercentMin.Equals(input.DenominationPercentMin))
                ) && 
                (
                    this.FloorAmountMax == input.FloorAmountMax ||
                    (this.FloorAmountMax != null &&
                    this.FloorAmountMax.Equals(input.FloorAmountMax))
                ) && 
                (
                    this.FloorAmountMin == input.FloorAmountMin ||
                    (this.FloorAmountMin != null &&
                    this.FloorAmountMin.Equals(input.FloorAmountMin))
                ) && 
                (
                    this.OriginAmountMax == input.OriginAmountMax ||
                    (this.OriginAmountMax != null &&
                    this.OriginAmountMax.Equals(input.OriginAmountMax))
                ) && 
                (
                    this.OriginAmountMin == input.OriginAmountMin ||
                    (this.OriginAmountMin != null &&
                    this.OriginAmountMin.Equals(input.OriginAmountMin))
                ) && 
                (
                    this.PublishEndTimeMax == input.PublishEndTimeMax ||
                    (this.PublishEndTimeMax != null &&
                    this.PublishEndTimeMax.Equals(input.PublishEndTimeMax))
                ) && 
                (
                    this.PublishEndTimeMin == input.PublishEndTimeMin ||
                    (this.PublishEndTimeMin != null &&
                    this.PublishEndTimeMin.Equals(input.PublishEndTimeMin))
                ) && 
                (
                    this.PublishStartTimeMax == input.PublishStartTimeMax ||
                    (this.PublishStartTimeMax != null &&
                    this.PublishStartTimeMax.Equals(input.PublishStartTimeMax))
                ) && 
                (
                    this.PublishStartTimeMin == input.PublishStartTimeMin ||
                    (this.PublishStartTimeMin != null &&
                    this.PublishStartTimeMin.Equals(input.PublishStartTimeMin))
                ) && 
                (
                    this.RefundType == input.RefundType ||
                    this.RefundType != null &&
                    input.RefundType != null &&
                    this.RefundType.SequenceEqual(input.RefundType)
                ) && 
                (
                    this.SaleAmountMax == input.SaleAmountMax ||
                    (this.SaleAmountMax != null &&
                    this.SaleAmountMax.Equals(input.SaleAmountMax))
                ) && 
                (
                    this.SaleAmountMin == input.SaleAmountMin ||
                    (this.SaleAmountMin != null &&
                    this.SaleAmountMin.Equals(input.SaleAmountMin))
                ) && 
                (
                    this.UseChannel == input.UseChannel ||
                    this.UseChannel != null &&
                    input.UseChannel != null &&
                    this.UseChannel.SequenceEqual(input.UseChannel)
                ) && 
                (
                    this.ValidDaysAfterReceiveMin == input.ValidDaysAfterReceiveMin ||
                    this.ValidDaysAfterReceiveMin.Equals(input.ValidDaysAfterReceiveMin)
                ) && 
                (
                    this.VoucherActivityType == input.VoucherActivityType ||
                    (this.VoucherActivityType != null &&
                    this.VoucherActivityType.Equals(input.VoucherActivityType))
                ) && 
                (
                    this.VoucherQuantityLimitPerUserMax == input.VoucherQuantityLimitPerUserMax ||
                    this.VoucherQuantityLimitPerUserMax.Equals(input.VoucherQuantityLimitPerUserMax)
                ) && 
                (
                    this.VoucherQuantityLimitPerUserMin == input.VoucherQuantityLimitPerUserMin ||
                    this.VoucherQuantityLimitPerUserMin.Equals(input.VoucherQuantityLimitPerUserMin)
                ) && 
                (
                    this.VoucherQuantityMax == input.VoucherQuantityMax ||
                    this.VoucherQuantityMax.Equals(input.VoucherQuantityMax)
                ) && 
                (
                    this.VoucherQuantityMin == input.VoucherQuantityMin ||
                    this.VoucherQuantityMin.Equals(input.VoucherQuantityMin)
                ) && 
                (
                    this.VoucherValidBeginTimeMin == input.VoucherValidBeginTimeMin ||
                    (this.VoucherValidBeginTimeMin != null &&
                    this.VoucherValidBeginTimeMin.Equals(input.VoucherValidBeginTimeMin))
                ) && 
                (
                    this.VoucherValidEndTimeMax == input.VoucherValidEndTimeMax ||
                    (this.VoucherValidEndTimeMax != null &&
                    this.VoucherValidEndTimeMax.Equals(input.VoucherValidEndTimeMax))
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
                if (this.AmountMax != null)
                {
                    hashCode = (hashCode * 59) + this.AmountMax.GetHashCode();
                }
                if (this.AmountMin != null)
                {
                    hashCode = (hashCode * 59) + this.AmountMin.GetHashCode();
                }
                if (this.DenominationPercentMax != null)
                {
                    hashCode = (hashCode * 59) + this.DenominationPercentMax.GetHashCode();
                }
                if (this.DenominationPercentMin != null)
                {
                    hashCode = (hashCode * 59) + this.DenominationPercentMin.GetHashCode();
                }
                if (this.FloorAmountMax != null)
                {
                    hashCode = (hashCode * 59) + this.FloorAmountMax.GetHashCode();
                }
                if (this.FloorAmountMin != null)
                {
                    hashCode = (hashCode * 59) + this.FloorAmountMin.GetHashCode();
                }
                if (this.OriginAmountMax != null)
                {
                    hashCode = (hashCode * 59) + this.OriginAmountMax.GetHashCode();
                }
                if (this.OriginAmountMin != null)
                {
                    hashCode = (hashCode * 59) + this.OriginAmountMin.GetHashCode();
                }
                if (this.PublishEndTimeMax != null)
                {
                    hashCode = (hashCode * 59) + this.PublishEndTimeMax.GetHashCode();
                }
                if (this.PublishEndTimeMin != null)
                {
                    hashCode = (hashCode * 59) + this.PublishEndTimeMin.GetHashCode();
                }
                if (this.PublishStartTimeMax != null)
                {
                    hashCode = (hashCode * 59) + this.PublishStartTimeMax.GetHashCode();
                }
                if (this.PublishStartTimeMin != null)
                {
                    hashCode = (hashCode * 59) + this.PublishStartTimeMin.GetHashCode();
                }
                if (this.RefundType != null)
                {
                    hashCode = (hashCode * 59) + this.RefundType.GetHashCode();
                }
                if (this.SaleAmountMax != null)
                {
                    hashCode = (hashCode * 59) + this.SaleAmountMax.GetHashCode();
                }
                if (this.SaleAmountMin != null)
                {
                    hashCode = (hashCode * 59) + this.SaleAmountMin.GetHashCode();
                }
                if (this.UseChannel != null)
                {
                    hashCode = (hashCode * 59) + this.UseChannel.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.ValidDaysAfterReceiveMin.GetHashCode();
                if (this.VoucherActivityType != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherActivityType.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.VoucherQuantityLimitPerUserMax.GetHashCode();
                hashCode = (hashCode * 59) + this.VoucherQuantityLimitPerUserMin.GetHashCode();
                hashCode = (hashCode * 59) + this.VoucherQuantityMax.GetHashCode();
                hashCode = (hashCode * 59) + this.VoucherQuantityMin.GetHashCode();
                if (this.VoucherValidBeginTimeMin != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherValidBeginTimeMin.GetHashCode();
                }
                if (this.VoucherValidEndTimeMax != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherValidEndTimeMax.GetHashCode();
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
